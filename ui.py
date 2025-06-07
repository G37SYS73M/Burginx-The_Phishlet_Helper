from burp import IMessageEditorController
from javax.swing import (
    JPanel, JList, DefaultListModel, JScrollPane, JTextArea,
    JSplitPane, JLabel, JButton, BoxLayout, ListSelectionModel
)
from java.awt import BorderLayout, Dimension

class MainPanel(JPanel):
    def __init__(self, callbacks):
        super(MainPanel, self).__init__(BorderLayout())
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()

        # Internal storage of IMessageInfo objects
        self.messages = []

        # Left: list of requests
        self.list_model = DefaultListModel()
        self.request_list = JList(self.list_model)
        # Use ListSelectionModel for selection constants
        self.request_list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.request_list.addListSelectionListener(lambda e: self.on_select_request())

        # Middle: raw request and response viewers
        self.request_view = JTextArea()
        self.request_view.setEditable(False)
        self.response_view = JTextArea()
        self.response_view.setEditable(False)

        # Bottom: placeholder for extraction controls
        self.extract_panel = JPanel()
        self.extract_panel.setLayout(BoxLayout(self.extract_panel, BoxLayout.Y_AXIS))
        self.extract_panel.add(JLabel("Extraction Controls Coming Soon..."))

        # Assemble split panes
        split_left = JScrollPane(self.request_list)
        split_right = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                                 JScrollPane(self.request_view),
                                 JScrollPane(self.response_view))
        split_right.setResizeWeight(0.5)

        right_panel = JPanel(BorderLayout())
        right_panel.add(split_right, BorderLayout.CENTER)
        right_panel.add(self.extract_panel, BorderLayout.SOUTH)

        main_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                                split_left, right_panel)
        main_split.setResizeWeight(0.3)
        main_split.setPreferredSize(Dimension(900, 600))

        # Top: button to queue selected history items into UI
        btn_panel = JPanel()
        send_btn = JButton("Send Selected to UI", actionPerformed=lambda e: self.send_selection())
        btn_panel.add(send_btn)

        # Overall layout
        self.add(btn_panel, BorderLayout.NORTH)
        self.add(main_split, BorderLayout.CENTER)

    def send_selection(self):
        """
        Stub: context menu or extender should call add_request() directly
        """
        pass

    def add_request(self, messageInfo):
        """
        Add a new HTTP request/response to the list and internal store.
        """
        idx = len(self.messages)
        self.messages.append(messageInfo)

        service = messageInfo.getHttpService()
        req_info = self.helpers.analyzeRequest(messageInfo)
        url = req_info.getUrl()
        display_text = "%d: %s %s" % (idx, service.getHost(), url)
        self.list_model.addElement(display_text)

    def on_select_request(self):
        """
        Display the raw request and response for the selected message.
        """
        sel = self.request_list.getSelectedIndex()
        if sel < 0 or sel >= len(self.messages):
            return
        messageInfo = self.messages[sel]
        req = messageInfo.getRequest()
        resp = messageInfo.getResponse()

        self.request_view.setText(self.helpers.bytesToString(req))
        self.response_view.setText(
            self.helpers.bytesToString(resp) if resp else ""
        )
