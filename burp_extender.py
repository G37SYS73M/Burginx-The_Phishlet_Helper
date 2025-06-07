from burp import IBurpExtender, ITab, IHttpListener
from javax.swing import SwingUtilities
from ui import MainPanel
import logic

class BurpExtender(IBurpExtender, ITab, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Phishlet Generator")

        # Initialize shared logic module
        logic.init(callbacks)

        # Build UI on Swing thread
        SwingUtilities.invokeLater(lambda: self._init_ui(callbacks))

        # Register as HTTP listener
        callbacks.registerHttpListener(self)

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
        # Pass history entries to logic module
        logic.on_message(toolFlag, messageIsRequest, messageInfo)