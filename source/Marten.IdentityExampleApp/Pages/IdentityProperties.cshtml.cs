using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Marten.IdentityExampleApp.Pages;

[Authorize]
public class IdentityProperties : PageModel
{
}