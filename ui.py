from javax.swing import JPanel, JButton, JTextArea, JLabel, JScrollPane, JFileChooser, BoxLayout
from java.awt import BorderLayout

class MainPanel(JPanel):
    def __init__(self, callbacks, logic):
        super(MainPanel, self).__init__(BorderLayout())
        self.callbacks = callbacks
        self.logic = logic

        # Top: Configuration
        config_panel = JPanel()
        config_panel.setLayout(BoxLayout(config_panel, BoxLayout.Y_AXIS))

        config_panel.add(JLabel("Trigger request index(es) (comma-separated):"))
        self.trigger_input = JTextArea(1, 30)
        config_panel.add(self.trigger_input)

        config_panel.add(JLabel("Error response regex pattern:"))
        self.error_input = JTextArea(1, 30)
        config_panel.add(self.error_input)

        self.extract_btn = JButton("Extract Tokens", actionPerformed=self.on_extract)
        config_panel.add(self.extract_btn)

        self.generate_btn = JButton("Generate YAML", actionPerformed=self.on_generate)
        config_panel.add(self.generate_btn)

        self.log_area = JTextArea(10, 50)
        self.log_area.setEditable(False)
        scroll = JScrollPane(self.log_area)

        self.add(config_panel, BorderLayout.NORTH)
        self.add(scroll, BorderLayout.CENTER)

    def on_extract(self, event):
        try:
            triggers = [int(x.strip()) for x in self.trigger_input.getText().split(",")]
        except:
            self.log("Invalid trigger indices format")
            return
        pattern = self.error_input.getText().strip()
        result = self.logic.extract(triggers, pattern)
        self.log("Extracted: %s" % repr(result))

    def on_generate(self, event):
        chooser = JFileChooser()
        chooser.setDialogTitle("Save Phishlet YAML")
        if chooser.showSaveDialog(self) == JFileChooser.APPROVE_OPTION:
            path = chooser.getSelectedFile().getAbsolutePath()
            self.logic.generate_yaml(path)
            self.log("YAML generated at %s" % path)

    def log(self, message):
        self.log_area.append(message + "\n")