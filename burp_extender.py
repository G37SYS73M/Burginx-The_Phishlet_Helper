from burp import IBurpExtender, ITab
from javax.swing import SwingUtilities
from ui import MainPanel

class BurpExtender(IBurpExtender, ITab):
    """
    Main Burp extension class that embeds the custom UI.
    """
    def registerExtenderCallbacks(self, callbacks):
        # Save callbacks and helpers
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()

        # Set extension name shown in Burp
        callbacks.setExtensionName("Phishlet Generator")

        # Initialize UI on the Swing EDT
        SwingUtilities.invokeLater(lambda: self._initialize_ui())

    def _initialize_ui(self):
        # Create the main UI panel and add it as a new tab
        self.main_panel = MainPanel(self.callbacks)
        self.callbacks.addSuiteTab(self)

    # ITab methods
    def getTabCaption(self):
        return "Phishlet Gen"

    def getUiComponent(self):
        return self.main_panel
