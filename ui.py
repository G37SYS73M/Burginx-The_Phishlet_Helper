from burp import IMessageEditorController
from javax.swing import (
    JPanel, JList, DefaultListModel, JScrollPane, JTextArea,
    JSplitPane, JLabel, JButton, BoxLayout, ListSelectionModel,
    JRadioButton, ButtonGroup, JTabbedPane, JFileChooser
)
from java.awt import BorderLayout, Dimension, FlowLayout
import logic

class MainPanel(JTabbedPane):
    def __init__(self, callbacks):
        super(MainPanel, self).__init__()
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.messages = []
        self.creds_list = []
        self.cookies_list = []
        self.list_model = DefaultListModel()

        self.extract_panel = self.build_extract_panel()
        self.yaml_panel = self.build_yaml_panel()
        self.addTab("Extract", self.extract_panel)
        self.addTab("Generate/Edit YAML", self.yaml_panel)

    def add_request(self, msg):
        idx = len(self.messages)
        self.messages.append(msg)
        svc = msg.getHttpService()
        info = self.helpers.analyzeRequest(msg)
        disp = "%d: %s %s" % (idx, svc.getHost(), info.getUrl())
        self.list_model.addElement(disp)

    def build_extract_panel(self):
        panel = JPanel(BorderLayout())
        top = JPanel(FlowLayout(FlowLayout.LEFT))
        clear = JButton("Clear Requests", actionPerformed=lambda e: self.clear_requests())
        top.add(clear); panel.add(top, BorderLayout.NORTH)

        self.request_list = JList(self.list_model)
        self.request_list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.request_list.addListSelectionListener(lambda e: self.on_select_request())
        list_scroll = JScrollPane(self.request_list)

        ctrl = JPanel(FlowLayout(FlowLayout.LEFT))
        self.radio_creds = JRadioButton("Creds")
        self.radio_cookies = JRadioButton("Cookies")
        grp = ButtonGroup(); grp.add(self.radio_creds); grp.add(self.radio_cookies)
        ctrl.add(self.radio_creds); ctrl.add(self.radio_cookies)
        get_btn = JButton("Get from Selection", actionPerformed=lambda e: self.on_extract_selection())
        ctrl.add(get_btn)

        left = JPanel(BorderLayout())
        left.add(list_scroll, BorderLayout.CENTER)
        left.add(ctrl, BorderLayout.SOUTH)

        self.request_view = JTextArea(); self.request_view.setEditable(False)
        self.response_view = JTextArea(); self.response_view.setEditable(False)
        viewer = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(self.request_view), JScrollPane(self.response_view))
        viewer.setResizeWeight(0.5)

        post_panel = JPanel(); post_panel.setLayout(BoxLayout(post_panel, BoxLayout.Y_AXIS))
        post_panel.add(JLabel("Extracted POST data"))
        self.post_area = JTextArea(4, 30); self.post_area.setEditable(False)
        post_panel.add(JScrollPane(self.post_area))

        token_panel = JPanel(); token_panel.setLayout(BoxLayout(token_panel, BoxLayout.Y_AXIS))
        token_panel.add(JLabel("Extracted Session Tokens"))
        self.token_area = JTextArea(4, 30); self.token_area.setEditable(False)
        token_panel.add(JScrollPane(self.token_area))

        result = JPanel(); result.setLayout(BoxLayout(result, BoxLayout.X_AXIS))
        result.add(post_panel); result.add(token_panel)

        content = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, JPanel(BorderLayout()))
        content.setResizeWeight(0.3)
        right = JPanel(BorderLayout())
        right.add(viewer, BorderLayout.CENTER); right.add(result, BorderLayout.SOUTH)
        content.setRightComponent(right)

        panel.add(content, BorderLayout.CENTER)
        return panel

    def build_yaml_panel(self):
        panel = JPanel(BorderLayout())
        self.yaml_text = JTextArea()
        panel.add(JScrollPane(self.yaml_text), BorderLayout.CENTER)
        btn_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
        gen_btn = JButton("Generate YAML", actionPerformed=lambda e: self.on_generate_yaml())
        save_btn = JButton("Save YAML", actionPerformed=lambda e: self.on_save_yaml())
        btn_panel.add(gen_btn); btn_panel.add(save_btn)
        panel.add(btn_panel, BorderLayout.SOUTH)
        return panel

    def on_select_request(self):
        sel = self.request_list.getSelectedIndex()
        if sel<0 or sel>=len(self.messages): return
        msg = self.messages[sel]
        self.request_view.setText(self.helpers.bytesToString(msg.getRequest()))
        self.response_view.setText(self.helpers.bytesToString(msg.getResponse()) if msg.getResponse() else "")

    def on_extract_selection(self):
        sel = self.request_list.getSelectedIndex()
        if sel<0: return
        if self.radio_creds.isSelected():
            s = self.request_view.getSelectedText()
            if s: self.creds_list.append(s)
            self.post_area.setText(", ".join(self.creds_list))
        if self.radio_cookies.isSelected():
            s = self.response_view.getSelectedText()
            if s: self.cookies_list.append(s)
            self.token_area.setText(", ".join(self.cookies_list))

    def clear_requests(self):
        self.messages.clear(); self.list_model.clear()
        self.request_view.setText(""); self.response_view.setText("")
        self.creds_list=[]; self.cookies_list=[]
        self.post_area.setText(""); self.token_area.setText("")

    def on_generate_yaml(self):
        urls = [self.helpers.analyzeRequest(msg).getUrl() for msg in self.messages]
        yaml = logic.build_phishlet_yaml(urls, self.creds_list, self.cookies_list)
        self.yaml_text.setText(yaml)

    def on_save_yaml(self):
        chooser = JFileChooser(); chooser.setDialogTitle("Save Phishlet YAML")
        if chooser.showSaveDialog(self)==JFileChooser.APPROVE_OPTION:
            path = chooser.getSelectedFile().getAbsolutePath()
            text = self.yaml_text.getText()
            f = open(path, 'w'); f.write(text); f.close()
