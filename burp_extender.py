from burp import IBurpExtender, ITab, IContextMenuFactory
from javax.swing import SwingUtilities, JMenuItem
from java.util import ArrayList
from ui import MainPanel
import logic

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Phishlet Generator")
        SwingUtilities.invokeLater(lambda: self._initialize_ui())
        callbacks.registerContextMenuFactory(self)

    def _initialize_ui(self):
        self.main_panel = MainPanel(self.callbacks)
        self.callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return "Phishlet Gen"

    def getUiComponent(self):
        return self.main_panel

    def createMenuItems(self, invocation):
        menu = ArrayList()
        item = JMenuItem("Send to Phishlet Gen",
                         actionPerformed=lambda e: self._send_to_ui(invocation))
        menu.add(item)
        return menu

    def _send_to_ui(self, invocation):
        for msg in invocation.getSelectedMessages():
            self.main_panel.add_request(msg)
