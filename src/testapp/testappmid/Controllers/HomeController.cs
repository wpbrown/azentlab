using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Principal;
using System.Web.Mvc;

namespace testapp.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            var user = (WindowsIdentity)User.Identity;
            ViewBag.Headers = GetHeaders();
            ViewBag.RemoteData = GetRemoteData(user);
            return View();
        }

        public ActionResult Api()
        {
            var user = (WindowsIdentity)User.Identity;

            var localData = new
            {
                Message = "Hello",
                user.Name,
                user.IsAuthenticated,
                user.AuthenticationType,
                ImpersonationLevel = user.ImpersonationLevel.ToString(),
                Headers = GetHeaders()
            };

            JObject remoteData = GetRemoteData(user);

            var data = new
            {
                IncomingUser = localData,
                BackendUser = remoteData
            };

            return Content(JsonConvert.SerializeObject(data), "application/json");
        }

        private static JObject GetRemoteData(WindowsIdentity user)
        {
            try
            {
                string remoteDataString;

                using (user.Impersonate())
                {
                    var request = WebRequest.Create("http://testapp/api");
                    request.UseDefaultCredentials = true;
                    request.ImpersonationLevel = TokenImpersonationLevel.Impersonation;
                    var response = request.GetResponse();
                    Stream dataStream = response.GetResponseStream();
                    var reader = new StreamReader(dataStream);
                    remoteDataString = reader.ReadToEnd();
                    reader.Close();
                    dataStream.Close();
                    response.Close();
                }

                return JObject.Parse(remoteDataString);
            }
            catch (Exception ex)
            {
                return new JObject
                {
                    new JProperty("error", ex.ToString())
                };
            }
        }

        private Dictionary<string, string> GetHeaders()
        {
            return Request.Headers.AllKeys.ToDictionary(k => k, k => Request.Headers[k]);
        }
    }
}