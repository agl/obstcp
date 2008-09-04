function LOG(text)
{
    var consoleService = Components.classes["@mozilla.org/consoleservice;1"].getService(Components.interfaces.nsIConsoleService);
    consoleService.logStringMessage(text);
}

function HTTPListener() { }

HTTPListener.prototype = {
  observe: function(subject, topic, data) {
      if (topic == "http-on-modify-request") {
          var httpChannel = subject.QueryInterface(Components.interfaces.nsIHttpChannel);
          httpChannel.setRequestHeader("X-ObsTCP", "request", false);
      } else if (topic == "http-on-examine-response") {
          var httpChannel = subject.QueryInterface(Components.interfaces.nsIHttpChannel);
          var host = subject.URI.asciiHost;
          try {
            var advert = httpChannel.getResponseHeader("X-ObsTCP-Advert");
            var prefManager = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch);
            prefManager.setCharPref("network.obstcp." + host, advert);
          } catch (ignore) { }
      } else if (topic == "app-startup") {
          var os = Components.classes["@mozilla.org/observer-service;1"].getService(Components.interfaces.nsIObserverService);
          os.addObserver(this, "http-on-modify-request", false);
          os.addObserver(this, "http-on-examine-response", false);
      }
  },

  QueryInterface: function (iid) {
        if (iid.equals(Components.interfaces.nsIObserver) ||
            iid.equals(Components.interfaces.nsISupports))
            return this;
        Components.returnCode = Components.results.NS_ERROR_NO_INTERFACE;
        return null;
    },
};

var module = {
    registerSelf: function (compMgr, fileSpec, location, type) {
        var compMgr = compMgr.QueryInterface(Components.interfaces.nsIComponentRegistrar);
        compMgr.registerFactoryLocation(this.CID,
                                        this.Name,
                                        this.ProgID,
                                        fileSpec,
                                        location,
                                        type);
        var catMgr = Components.classes["@mozilla.org/categorymanager;1"].getService(Components.interfaces.nsICategoryManager);
        catMgr.addCategoryEntry("app-startup", this.Name, this.ProgID, true, true);
    },


    getClassObject: function (compMgr, cid, iid) {
        return this.factory;
    },

    CID: Components.ID("{2512e6fa-9b6b-43f0-9558-e8578e34b88c}"),
    ProgID: "@agl/HTTPListener;1",
    Name: "ObsTCP HTTP Request mutator",

    factory: {
        QueryInterface: function (aIID) {
            if (!aIID.equals(Components.interfaces.nsISupports) &&
                !aIID.equals(Components.interfaces.nsIFactory))
                throw Components.results.NS_ERROR_NO_INTERFACE;
            return this;
        },

        createInstance: function (outer, iid) {
          return new HTTPListener();
        }
    },

    canUnload: function(compMgr) {
        return true;
    }
};

function NSGetModule(compMgr, fileSpec) {
    return module;
}
