using System.Security.Principal;
using System.Web.Mvc;
using System.Linq;
using System.Collections.Generic;

namespace testapp.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            ViewBag.Headers = GetHeaders();
            return View();
        }

        public ActionResult Api()
        {
            var user = (WindowsIdentity)User.Identity;
            var data = new
            {
                Message = "Hello",
                user.Name,
                user.IsAuthenticated,
                user.AuthenticationType,
                ImpersonationLevel = user.ImpersonationLevel.ToString(),
                Headers = GetHeaders()
            };

            return Json(data, JsonRequestBehavior.AllowGet);
        }

        private Dictionary<string, string> GetHeaders()
        {
            return Request.Headers.AllKeys.ToDictionary(k => k, k => Request.Headers[k]);
        }
    }
}