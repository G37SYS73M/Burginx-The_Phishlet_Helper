from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory
from javax.swing import SwingUtilities, JMenuItem
from java.util import ArrayList
from ui import MainPanel
import logic

class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Phishlet Generator")

        # Initialize shared logic module
        logic.init(callbacks)

        # Build UI on Swing thread
        SwingUtilities.invokeLater(lambda: self._init_ui(callbacks))

        # Register as HTTP listener and context menu factory
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)

    def _init_ui(self, callbacks):
        self.main_panel = MainPanel(callbacks, logic)
        callbacks.addSuiteTab(self)

    # ITab methods
    def getTabCaption(self):
        return "Phishlet Gen"

    def getUiComponent(self):
        return self.main_panel

    # IHttpListener method
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Store all history entries by default
        logic.on_message(toolFlag, messageIsRequest, messageInfo)

    # IContextMenuFactory method
    def createMenuItems(self, invocation):
        menu = ArrayList()
        item = JMenuItem("Send to Phishlet Gen", actionPerformed=lambda event: self._send_to_phishlet(invocation))
        menu.add(item)
        return menu

    def _send_to_phishlet(self, invocation):
        messages = invocation.getSelectedMessages()
        sent_indices = []
        for msg in list(messages):
            idx = logic.store_from_context(invocation.getToolFlag(), msg)
            sent_indices.append(idx)
        self.main_panel.log("Queued messages for extraction: %s" % sent_indices)
