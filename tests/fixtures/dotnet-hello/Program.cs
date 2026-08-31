using Newtonsoft.Json;
var o = new { dotnet = "ok" };
Console.WriteLine("dn real: " + JsonConvert.SerializeObject(o));
