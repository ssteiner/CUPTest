using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using PresenceTester.PresenceServer;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using System.Net;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Xml;

namespace PresenceTester
{
    public class PresenceConnector
    {

        PresenceServerConfiguration configuration;
        PresenceSoapPortTypeClient server;
        string adminSessionId, userSessionId, callbckServerAddress = "http://10.145.42.33:8088/";
        SimpleWebServer.WebServer callbackServer;
        int endPointId, subscriptionId;

        public PresenceConnector(PresenceServerConfiguration configuration)
        {
            this.configuration = configuration;
            //callbackServer = new SimpleWebServer.WebServer(SendHttpResponse, callbckServerAddress);
        }

        public void Init()
        {
            ServicePointManager.ServerCertificateValidationCallback += validatedCertificate;
            server = new PresenceSoapPortTypeClient();
            string absoluteUrl = server.Endpoint.Address.Uri.AbsoluteUri;
            absoluteUrl = absoluteUrl.Replace(server.Endpoint.Address.Uri.Host, configuration.PrimaryAddress);
            if (configuration.UseHttp)
            {
                if (string.Compare(server.Endpoint.Address.Uri.Scheme, "http", true) != 0)
                    absoluteUrl = absoluteUrl.Replace(server.Endpoint.Address.Uri.Scheme, "http");
                if (server.Endpoint.Address.Uri.Port != configuration.HttpPort)
                    absoluteUrl = absoluteUrl.Replace(server.Endpoint.Address.Uri.Port.ToString(), configuration.HttpPort.ToString());
                if (server.Endpoint.Binding.Scheme == "https")
                    server.Endpoint.Binding = new BasicHttpBinding();
                //((BasicHttpBinding)server.Endpoint.Binding).UseDefaultWebProxy = false;

            }
            else
            {
                if (string.Compare(server.Endpoint.Address.Uri.Scheme, "https", true) != 0)
                    absoluteUrl = absoluteUrl.Replace(server.Endpoint.Address.Uri.Scheme, "https");
                if (server.Endpoint.Address.Uri.Port != configuration.HttpsPort)
                    absoluteUrl = absoluteUrl.Replace(server.Endpoint.Address.Uri.Port.ToString(), configuration.HttpsPort.ToString());
                if (server.Endpoint.Binding.Scheme == "http")
                    server.Endpoint.Binding = new BasicHttpsBinding();
                //((BasicHttpsBinding)server.Endpoint.Binding).UseDefaultWebProxy = false;
            }
            server.Endpoint.Binding.OpenTimeout = TimeSpan.FromSeconds(10);
            server.Endpoint.Address = new EndpointAddress(absoluteUrl);

            //callbackServer.Run();

        }

        public void Destroy()
        {
            callbackServer.Stop();
        }

        #region open/close sessions

        public LoginResult EstablishAdminSession(bool allowRetry = true)
        {
            login loginParameters = new login { forceSpecified = true, force = true, Item = configuration.Login, ItemElementName = ItemChoiceType.password, username = configuration.Password };
            return performLogin(loginParameters, allowRetry);
        }

        public LoginResult EstablishUserSession(string sessionId, string userId, bool allowRetry = true)
        {
            login loginParameters = new login { forceSpecified = true, force = true, Item = sessionId, ItemElementName = ItemChoiceType.appsessionid, username = userId };
            return performLogin(loginParameters, allowRetry);
        }

        private LoginResult performLogin(login loginParameters, bool allowRetry = true)
        {
            LoginResult result = new LoginResult();
            try
            {
                LoginResponse res = server.login(loginParameters);
                if (res.Item is LoginResponseSuccess)
                {
                    LoginResponseSuccess loginResponse = res.Item as LoginResponseSuccess;
                    result.SessionId = loginResponse.sessionkey;
                    result.ResultCode = LoginResultCode.Success;
                }
                else if (res.Item is LoginResponseRedirect)
                {
                    LoginResponseRedirect redirect = res.Item as LoginResponseRedirect;
                    log("login for " + (loginParameters.ItemElementName == ItemChoiceType.password ? loginParameters.Item : loginParameters.username) +
                        " was redirected from server " + configuration.PrimaryAddress + " to " + redirect.primaryServer, 3);
                    if (allowRetry)
                    {
                        configuration.PrimaryAddress = redirect.primaryServer;
                        configuration.SecondaryAddress = redirect.backupServer;
                        return EstablishAdminSession(false);
                    }
                }
            }
            catch (FaultException f)
            {
                log("Error received during login processing: " + f.Message, 2);
                result.ResultCode = LoginResultCode.ApiFault;
            }
            catch (CommunicationException c)
            {
                log("Communication error: " + c.Message, 2);
                result.ResultCode = LoginResultCode.CommunicationError;
                if (allowRetry)
                {
                    string tempAddress = configuration.SecondaryAddress;
                    configuration.PrimaryAddress = configuration.SecondaryAddress;
                    configuration.SecondaryAddress = tempAddress;
                    return EstablishAdminSession(false);
                }
            }
            return result;
        }

        public PresenceApiIntegerResult Logout(string sessionId)
        {
            PresenceApiIntegerResult result = new PresenceApiIntegerResult();
            try
            {
                ResponseStatusType resType = server.logout(sessionId, new logout { });
                if (resType.status == ResponseStatusTypeStatus.SUCCESS)
                    result.ResultCode = GenericPresenceApiResultCode.Success;
                else
                    result.ResultCode = GenericPresenceApiResultCode.ApiFault;
            }
            catch (FaultException f)
            {
                log("Error received during logout processing: " + f.Message, 2);
                result.ResultCode = GenericPresenceApiResultCode.ApiFault;
            }
            catch (CommunicationException c)
            {
                log("Communication error: " + c.Message, 2);
                result.ResultCode = GenericPresenceApiResultCode.CommunicationError;
            }
            return result;
        }

        #endregion

        #region endpoints

        public PresenceApiIntegerResult ExtendEndpointRegistration(string sessionId, int endPointId, int expiration)
        {
            registerEndPoint registrationMessage = new registerEndPoint 
            {
                expiration = fixExpiration(expiration), 
                endPointID = endPointId
            };
            return performEndPointRegistration(sessionId, registrationMessage);
        }

        public PresenceApiIntegerResult RegisterEndPoint(string sessionId, int expiration)
        {
            return RegisterEndPoint(sessionId, expiration, null);
        }

        public PresenceApiIntegerResult RegisterEndPoint(string sessionId, int expiration, string address = null)
        {
            registerEndPoint registrationMessage = new registerEndPoint 
            {
                expiration = fixExpiration(expiration), 
                url = (string.IsNullOrEmpty(address) ? callbckServerAddress : address) 
            };
            return performEndPointRegistration(sessionId, registrationMessage);
        }

        private PresenceApiIntegerResult performEndPointRegistration(string sessionId, registerEndPoint registrationMessage)
        {
            PresenceApiIntegerResult result = new PresenceApiIntegerResult();
            try
            {
                registerEndPointResponse endpointRes = server.registerEndPoint(sessionId, registrationMessage);
                result.IntegerId = endpointRes.endPointID;
                result.ResultCode = GenericPresenceApiResultCode.Success;
            }
            catch (FaultException f)
            {
                log("API error during registerEndPoint: " + f.Message, 2);
                result.ResultCode = GenericPresenceApiResultCode.ApiFault;
            }
            catch (CommunicationException c)
            {
                log("Communication error: " + c.Message, 2);
                result.ResultCode = GenericPresenceApiResultCode.CommunicationError;
            }
            return result;
        }

        public PresenceApiIntegerResult UnregisterEndPoint(string sessionId, int endpointId)
        {
            PresenceApiIntegerResult result = new PresenceApiIntegerResult();
            try
            {
                ResponseStatusType resType = server.unregisterEndPoint(sessionId, new unregisterEndPoint { endPointID = endpointId });
                if (resType.status == ResponseStatusTypeStatus.SUCCESS)
                    result.ResultCode = GenericPresenceApiResultCode.Success;
                else
                    result.ResultCode = GenericPresenceApiResultCode.ApiFault;
            }
            catch (FaultException f)
            {
                log("API error during unregisterEndPoint: " + f.Message, 2);
                result.ResultCode = GenericPresenceApiResultCode.ApiFault;
            }
            catch (CommunicationException c)
            {
                log("Communication error: " + c.Message, 2);
                result.ResultCode = GenericPresenceApiResultCode.CommunicationError;
            }
            return result;
        }

        #endregion

        private int fixExpiration(int expiration)
        {
            if (expiration < 0)
                return 3600;
            else if (expiration > 86400)
                return 86400;
            return expiration;
        }

        #region event subscriptions

        public PresenceApiIntegerResult AddContactsToSubscription(string sessionId, int endPointId, List<string> contactList, int subscriptionId)
        {
            subscribe subscribeRequest = new subscribe
            {
                contactsList = generateContactList(contactList),
                endPointID = endPointId,
                expirationSpecified = false,
                subscriptionID = subscriptionId,
                subscriptionType = "PRESENCE_NOTIFICATION"
            };
            return performSubscription(sessionId, subscribeRequest);
        }

        public PresenceApiIntegerResult Subscribe(string sessionId, int endPointId, int expiration, List<string> contactList)
        {
            subscribe subscribeRequest = new subscribe
            {
                contactsList = generateContactList(contactList),
                endPointID = endPointId,
                expiration = fixExpiration(expiration),
                expirationSpecified = true,
                subscriptionID = 0,
                subscriptionType = "PRESENCE_NOTIFICATION"
            };
            return performSubscription(sessionId, subscribeRequest);
        }

        private PresenceApiIntegerResult performSubscription(string sessionId, subscribe subscribeRequest)
        {
            PresenceApiIntegerResult result = new PresenceApiIntegerResult();
            try
            {
                subscribeResponse subRes = server.subscribe(sessionId, subscribeRequest);
                result.IntegerId = subRes.subscriptionID;
                result.ResultCode = GenericPresenceApiResultCode.Success;
            }
            catch (FaultException f)
            {
                log("API error during subscribe: " + f.Message, 2);
                result.ResultCode = GenericPresenceApiResultCode.ApiFault;
            }
            catch (CommunicationException c)
            {
                log("Communication error: " + c.Message, 2);
                result.ResultCode = GenericPresenceApiResultCode.CommunicationError;
            }
            return result;
        }

        private Contact[] generateContactList(List<string> list)
        {
            List<Contact> contactList = new List<Contact>();
            foreach (string userId in list)
            {
                contactList.Add(new Contact { contactURI = userId });
            }
            return contactList.ToArray();
        }

        public PresenceApiIntegerResult UnsubscribeAll(string sessionId, int subscriptionId)
        {
            unsubscribe unsubscribeRequest = new unsubscribe { unsubscribeRequest = new UnsubscribeRequest { subscriptionID = subscriptionId, Item = true } };
            return performUnsubscription(sessionId, unsubscribeRequest);
        }

        public PresenceApiIntegerResult Unsubscribe(string sessionId, int subscriptionId, List<string> contacts)
        {
            unsubscribe unsubscribeRequest = new unsubscribe { unsubscribeRequest = new UnsubscribeRequest { subscriptionID = subscriptionId, Item = generateContactList(contacts) } };
            return performUnsubscription(sessionId, unsubscribeRequest);
        }

        private PresenceApiIntegerResult performUnsubscription(string sessionId, unsubscribe unsubscribeRequest)
        {
            PresenceApiIntegerResult result = new PresenceApiIntegerResult();
            try
            {
                ResponseStatusType resType = server.unsubscribe(sessionId, unsubscribeRequest);
                if (resType.status == ResponseStatusTypeStatus.SUCCESS)
                    result.ResultCode = GenericPresenceApiResultCode.Success;
                else
                    result.ResultCode = GenericPresenceApiResultCode.ApiFault;
            }
            catch (FaultException f)
            {
                log("API error during unsubscribe: " + f.Message, 2);
                result.ResultCode = GenericPresenceApiResultCode.ApiFault;
            }
            catch (CommunicationException c)
            {
                log("Communication error: " + c.Message, 2);
                result.ResultCode = GenericPresenceApiResultCode.CommunicationError;
            }
            return result;
        }

        #endregion

        private void log(string message, int severity)
        {
            Console.WriteLine(message);
        }

        public bool StartTest2()
        {
            LoginResult adminLoginRes, userLoginRes;
            adminLoginRes = EstablishAdminSession();
            if (adminLoginRes.ResultCode == LoginResultCode.Success)
            {
                adminSessionId = adminLoginRes.SessionId;
                log("Successfully logged in admin", 4);
                PresenceApiIntegerResult registerResult = RegisterEndPoint(adminLoginRes.SessionId, 3600);
                if (registerResult.ResultCode == GenericPresenceApiResultCode.Success)
                {
                    endPointId = registerResult.IntegerId;
                    log("Successfully registered endpoint " + callbckServerAddress + ", endpoint id " + endPointId, 4);
                    userLoginRes = EstablishUserSession(adminLoginRes.SessionId, "sste-dect");
                    if (userLoginRes.ResultCode == LoginResultCode.Success)
                    {
                        log("Successfully logged in user sste-dect", 4);
                        userSessionId = userLoginRes.SessionId;
                        PresenceApiIntegerResult subscribeResult = Subscribe(userSessionId, endPointId, 3600, new List<string> { "sste-dect@chzhlab.ch", "sste@chzhlab.ch" });
                        if (subscribeResult.ResultCode == GenericPresenceApiResultCode.Success)
                        {
                            subscriptionId = subscribeResult.IntegerId;
                            log("Successfully started event subscription, id " + subscriptionId, 4);
                            return true;
                        }
                        else
                            log("Unable to start event subscription: " + subscribeResult.ResultCode, 2);
                    }
                    else
                    {
                        log("Unable to log in user sste-dect@chzhlab.ch", 2);
                    }
                }
                else
                {
                    log("Unable to register endpoint " + callbckServerAddress + ": " + registerResult.ResultCode, 2);
                }
            }
            else
            {
                log("Unable to log in admin user: " + adminLoginRes.ResultCode, 2);
            }
            EndTest2();
            return false;
        }

        public void EndTest2()
        {
            if (!string.IsNullOrEmpty(adminSessionId))
            {
                if (!string.IsNullOrEmpty(userSessionId))
                {
                    if (subscriptionId != 0)
                    {
                        PresenceApiIntegerResult unsubscribeResult = UnsubscribeAll(userSessionId, subscriptionId);
                        log("Result of event unsubscription: " + unsubscribeResult.ResultCode, 4);
                    }
                    PresenceApiIntegerResult logoutResult = Logout(userSessionId);
                    log("Result of user logout: " + logoutResult.ResultCode, 4);
                }

                if (endPointId != 0)
                {
                    PresenceApiIntegerResult unregisterResult = UnregisterEndPoint(adminSessionId, endPointId);
                    log("Result of endpoint unregister: " + unregisterResult.ResultCode, 4);
                }

                PresenceApiIntegerResult logoutResult2 = Logout(adminSessionId);
                log("Result of admin logout: " + logoutResult2.ResultCode, 4);
            }
        }

        /// <summary>
        /// getting and setting some presence states
        /// </summary>
        public void Test()
        {

            login loginParameters = new login 
            { 
                forceSpecified = 
                true, force = true, 
                Item = configuration.Login, 
                ItemElementName = ItemChoiceType.password, 
                username = configuration.Password 
            };

            loginParameters.forceSpecified = true;
            loginParameters.force = true;

            //log into the server as admin
            LoginResponse res = server.login(loginParameters);

            if (res.Item is LoginResponseSuccess)
            {
                LoginResponseSuccess succ = res.Item as LoginResponseSuccess;

                adminSessionId = succ.sessionkey;
                string userSessionId;
                ResponseStatusType resType = null;
                //now perform the per user login
                res = server.login(new login 
                { 
                    Item = adminSessionId, 
                    ItemElementName = ItemChoiceType.appsessionid, 
                    username = "lsste", 
                    forceSpecified = true, 
                    force = true 
                });
                if (res.Item is LoginResponseSuccess)
                {
                    succ = res.Item as LoginResponseSuccess;
                    userSessionId = succ.sessionkey;

                    getPolledPresence req = new getPolledPresence { presenceType = "BASIC_PRESENCE" };
                    //req.presenceType = "RICH_PRESENCE";
                    // other presence type RICH_PRESENCE

                    Contact myContact = new Contact { contactURI = "lsste@nxodev.intra" }; // replace that with the user you want to get presence from
                    Contact myContact2 = new Contact { contactURI = "wengerpe@nxodev.intra" };

                    req.contactsList = new Contact[] { myContact };
                    getPolledPresenceResponse presRes = server.getPolledPresence(userSessionId, req);

                    presRes = server.getPolledPresence(userSessionId, new getPolledPresence 
                    { 
                        contactsList = new Contact[] { myContact }, 
                        presenceType = "RICH_PRESENCE" 
                    });

                    //registerEndPointResponse endpointRes = server.registerEndPoint(adminSessionId, new registerEndPoint 
                    //{ 
                    //    expiration = 86400, 
                    //    url = callbckServerAddress 
                    //});
                    //endPointId = endpointRes.endPointID;
                    //resType = server.setPresence(userSessionId, new setPresence 
                    //{ 
                    //    presenceType = "BASIC_PRESENCE", 
                    //    expiration = 86400, 
                    //    presenceInfo = new PresenceInfoType 
                    //    { 
                    //        basicPresence = "BUSY", 
                    //        @override = false 
                    //    } 
                    //});

                    //resType = server.setPresence(userSessionId, new setPresence 
                    //{ 
                    //    presenceType = "BASIC_PRESENCE", 
                    //    expiration = 86400, 
                    //    presenceInfo = new PresenceInfoType 
                    //    { 
                    //        basicPresence = "AWAY", 
                    //        @override = true 
                    //    } 
                    //});

                    //and now we're trying to set the presence state
                    string presString = generateOnThePhonePresenceString("lsste", "nxodev.intra");
                    presString = generateIdlePresenceString("lsste", "nxodev.intra");
                    presString = generateAwayPresenceString("lsste", "nxodev.intra");
                    var xml = new System.Xml.XmlDocument();
                    xml.LoadXml(presString);

                    setPresence presenceState = new setPresence
                    {
                        presenceType = "RICH_PRESENCE",
                        expiration = 3600,
                        presenceInfo = new PresenceInfoType
                            {
                                @override = true,
                                richPresence = xml.OuterXml
                            }
                    };
                    try
                    {
                        resType = server.setPresence(userSessionId, presenceState);
                    }
                    catch (FaultException f)
                    {
                        MessageFault fault = f.CreateMessageFault();
                        XmlElement elem = fault.GetDetail<XmlElement>();
                        log("Unable to set presence: " + f.Message, 2);
                    }

                    presenceState = new setPresence
                    {
                        presenceType = "RICH_PRESENCE",
                        expiration = 3600,
                        presenceInfo = new PresenceInfoType
                        {
                            @override = true,
                            richPresence = generateIdlePresenceString("sste", "chzhlab.ch")
                        }
                    };

                    try
                    {

                        resType = server.setPresence(userSessionId, presenceState);
                    }
                    catch (FaultException f)
                    {
                        MessageFault fault = f.CreateMessageFault();
                        XmlElement elem = fault.GetDetail<XmlElement>();
                        log("Unable to set presence: " + f.Message, 2);
                    }

                    presenceState.presenceInfo.richPresence = generatePresenceState("sste", "chzhlab.ch", "unavailable", false, true);

                    try
                    {

                        resType = server.setPresence(userSessionId, presenceState);
                    }
                    catch (FaultException f)
                    {
                        MessageFault fault = f.CreateMessageFault();
                        XmlElement elem = fault.GetDetail<XmlElement>();
                        log("Unable to set presence: " + f.Message, 2);
                    }

                    presenceState = new setPresence
                    {
                        presenceType = "RICH_PRESENCE",
                        expiration = 3600,
                        presenceInfo = new PresenceInfoType
                        {
                            @override = true,
                            richPresence = generatePresenceState("sste", "chzhlab.ch", "away", false, false)
                        }
                    };

                    try
                    {

                        resType = server.setPresence(userSessionId, presenceState);
                    }
                    catch (FaultException f)
                    {
                        MessageFault fault = f.CreateMessageFault();
                        XmlElement elem = fault.GetDetail<XmlElement>();
                        log("Unable to set presence: " + f.Message, 2);
                    }

                    presenceState.presenceInfo.richPresence = generatePresenceState("sste", "chzhlab.ch", "away", false, true);

                    try
                    {

                        resType = server.setPresence(userSessionId, presenceState);
                    }
                    catch (FaultException f)
                    {
                        MessageFault fault = f.CreateMessageFault();
                        XmlElement elem = fault.GetDetail<XmlElement>();
                        log("Unable to set presence: " + f.Message, 2);
                    }

                    //subscribeResponse subRes = server.subscribe(userSessionId, new subscribe
                    //{
                    //    contactsList = new Contact[] { myContact },
                    //    endPointID = endPointId,
                    //    expiration = 86400,
                    //    expirationSpecified = true,
                    //    subscriptionID = 0,
                    //    subscriptionType = "PRESENCE_NOTIFICATION"
                    //});

                    //resType = server.unsubscribe(userSessionId, new unsubscribe { unsubscribeRequest = new UnsubscribeRequest { subscriptionID = subRes.subscriptionID, Item = true } });

                    //resType = server.unregisterEndPoint(adminSessionId, new unregisterEndPoint { endPointID = endPointId });

                    resType = server.logout(userSessionId, new logout { });

                    resType = server.logout(adminSessionId, new logout { });
                }

                Console.WriteLine("Result of logout: " + resType.status);
            }
            else if (res.Item is LoginResponseRedirect)
            {
                LoginResponseRedirect redirect = res.Item as LoginResponseRedirect;
            }
        }


        private string generatePresenceState(string userId, string sipDomain, string state, bool onThePhone, bool force)
        {
            string presenceValue = 
                "<presence xmlns=\"urn:ietf:params:xml:ns:pidf\" " +
                //"xmlns:rp=\"urn:ietf:params:xml:ns:pidf:rpid\" " +
                //"xmlns:dm=\"urn:ietf:params:xml:ns:pidf:data-model\" " +
                "xmlns:ce=\"urn:cisco:params:xml:ns:pidf:rpid\" " +
                "xmlns:so=\"urn:cisco:params:xml:ns:pidf:source\" " +
                "xmlns:sc=\"urn:ietf:params:xml:ns:pidf:servcaps\" " +
                "entity=\"" + userId + "@" + sipDomain + "\">" +
                "<ce:person id=\"" + userId + "\">" +
                "<ce:activities><" + state + "/>" + (onThePhone ? "<ce:on-the-phone/>" : string.Empty) + "</ce:activities>" +
                "</ce:person>" +
                "<tuple id=\"" + (force ? "pws-override" : "cisco-pws") + "\">" +
                "<so:source>Presence Web Service</so:source>" +
                "<status>" +
                "<basic>closed</basic>" +
                "</status>" +
                "<sc:servcaps><sc:audio>true</sc:audio></sc:servcaps>" +
                "</tuple>" +
                "</presence>";

            return presenceValue;
        }

        private string generateOnThePhonePresenceString(string userId, string sipDomain)
        {
            string presenceValue =
                "<presence xmlns=\"urn:ietf:params:xml:ns:pidf\" " +
                //"xmlns:rp=\"urn:ietf:params:xml:ns:pidf:rpid\" " +
                //"xmlns:dm=\"urn:ietf:params:xml:ns:pidf:data-model\" " +
                //"xmlns:ce=\"urn:cisco:params:xml:ns:pidf:rpid\" " +
                //"xmlns:so=\"urn:cisco:params:xml:ns:pidf:source\" " +
                //"xmlns:sc=\"urn:ietf:params:xml:ns:pidf:servcaps\" " +
                "entity=\"sip:" + userId + "@" + sipDomain + "\">" +
                "<person xmlns=\"urn:cisco:params:xml:ns:pidf:rpid\" id=\"" + userId + "\">" +
                "<activities><busy/></activities>" +
                "</person>" +
                "<tuple xmlns=\"urn:ietf:params:xml:ns:pidf\" id=\"pws-override\">" +
                //"<source xmlns=\"urn:cisco:params:xml:ns:pidf:source\">Presence Web Service</source>" +
                "<status>" +
                "<basic>open</basic>" +
                "</status>" +
                "<servcaps xmlns=\"urn:ietf:params:xml:ns:pidf:servcaps\"><audio>true</audio></servcaps>" +
                "</tuple>" +
                "</presence>";

            return presenceValue;
        }

        private string generateAwayPresenceString(string userId, string sipDomain)
        {
            string presenceValue = "<presence entity=\"sip:" + userId + "@" + sipDomain + "\" xmlns=\"urn:ietf:params:xml:ns:pidf\">"
                + "<person id=\"" + userId + "\" xmlns=\"urn:cisco:params:xml:ns:pidf:rpid\">"
                + "<activities>"
                + "<available/>"
                + "<phone-status>unavailable</phone-status>"
                + "<im-status>available</im-status>"
                + "</activities>"
                + "</person>"
                + "<displayname xmlns=\"urn:ietf:params:xml:ns:pidf:cipid\">" + userId + "@" + sipDomain + "</displayname>"
                + "<tuple id=\"JabberJabber MomentIM\" xmlns=\"urn:ietf:params:xml:ns:pidf\">"
                + "<status>" 
                + "<basic>open</basic>"
                + "</status>"
                + "<servcaps xmlns=\"urn:ietf:params:xml:ns:pidf:servcaps\">"
                + "<type>text/plain</type>"
                + "<type>application/x-cisco-cupc+xml</type>"
                + "<text>true</text>"
                + "</servcaps>"
                + "</tuple>"
                + "</presence>";
            return presenceValue;
        }

        private string generateIdlePresenceString(string userId, string sipDomain)
        {
            string presenceValue =
                "<presence xmlns=\"urn:ietf:params:xml:ns:pidf\" " +
                //"xmlns:rp=\"urn:ietf:params:xml:ns:pidf:rpid\" " +
                //"xmlns:dm=\"urn:ietf:params:xml:ns:pidf:data-model\" " +
                "xmlns:ce=\"urn:cisco:params:xml:ns:pidf:rpid\" " +
                "xmlns:so=\"urn:cisco:params:xml:ns:pidf:source\" " +
                "xmlns:sc=\"urn:ietf:params:xml:ns:pidf:servcaps\" " +
                "entity=\"sip:" + userId + "@" + sipDomain + "\">" +
                "<ce:person id=\"" + userId + "\">" +
                "</ce:person>" +
                "<tuple id=\"cisco-pws\">" +
                "<so:source>Presence Web Service</so:source>" +
                "<status>" +
                "<basic>open</basic>" +
                "</status>" +
                "<sc:servcaps><sc:audio>true</sc:audio></sc:servcaps>" +
                "</tuple>" +
                "</presence>";

            return presenceValue;
        }


        public string SendHttpResponse(HttpListenerRequest request)
        {
            if (request.QueryString.Count == 2)
            {
                string subscriptionId = request.QueryString[0];
                string eventType = request.QueryString[1];
            }
            return "OK";
        }



        private bool validatedCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }
    }


    public class LoginResult
    {
        public string SessionId { get; set; }
        public LoginResultCode ResultCode { get; set; }

        public LoginResult()
        {
            ResultCode = LoginResultCode.GenericError;
        }
    }

    public enum LoginResultCode
    {
        Success, ApiFault, CommunicationError, GenericError
    }

    public class PresenceApiIntegerResult
    {
        public int IntegerId { get; set; }
        public GenericPresenceApiResultCode ResultCode { get; set; }

        public PresenceApiIntegerResult()
        {
            ResultCode = GenericPresenceApiResultCode.GenericError;
        }
    }

    public enum GenericPresenceApiResultCode
    {
        Success, ApiFault, CommunicationError, GenericError
    }


}
