#r "itextsharp.dll"
#r "Newtonsoft.Json"

using Newtonsoft.Json;
using System.Net;
using System.Net.Http;

using System.IO;
using System.Text;

using javax.xml.transform;
using javax.xml.transform.stream;
using javax.xml.transform.sax;
using org.apache.fop.apps;
using java.io;
using java.net;
using org.apache.fop.fonts;
using org.apache.fop.apps.io;
using org.apache.avalon.framework.configuration;

using Org.BouncyCastle.Pkcs;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;

public static async Task<HttpResponseMessage> Run(HttpRequestMessage req, TraceWriter log, ExecutionContext context)
{
   string homeloc = context.FunctionDirectory;

   log.Info("C# HTTP trigger function FOP processed a request - home loc is "+homeloc);


   dynamic body = req.Content.ReadAsStringAsync().Result;
   dynamic json = JsonConvert.DeserializeObject(body);
   string xml = json.xml;
   xml = WebUtility.HtmlDecode(xml);

   // Removing possible BOM chars
   int index = xml.IndexOf('<');
   if (index > 0)
   {
       xml = xml.Substring(index, xml.Length - index);
   }
   string xsl = json.xsl;
   //xsl = WebUtility.HtmlDecode(xsl);
   WebClient wc = new WebClient();
   wc.Encoding = System.Text.Encoding.UTF8;
   byte[] xslba = new WebClient().DownloadData(xsl);

log.Info("...received xsl:"+xsl);

   ByteArrayOutputStream baos = new ByteArrayOutputStream();
   DefaultConfigurationBuilder cfgBuilder = new DefaultConfigurationBuilder();
   Configuration cfg = cfgBuilder.buildFromFile(new java.io.File(homeloc+"/userconfig.xml"));
   FopFactoryBuilder fopFactoryBuilder = new FopFactoryBuilder(new java.io.File(homeloc).toURI()).setConfiguration(cfg);

   URI fontBase = new URI("file", "///" + homeloc.Replace("\\", "/") + "/", null);
   FontManager fontManager = fopFactoryBuilder.getFontManager();
   InternalResourceResolver resourceResolver = ResourceResolverFactory
      .createInternalResourceResolver(fontBase, ResourceResolverFactory.createDefaultResourceResolver());
   fontManager.setResourceResolver(resourceResolver);

   string fopcacheFilePath = homeloc+"/fop-fonts.cache";

   fopcacheFilePath = fopcacheFilePath.Replace("\\", "/");
   fopcacheFilePath = "file:///" + fopcacheFilePath;
   fopcacheFilePath = fopcacheFilePath.Replace(" ", "%20");
   fopFactoryBuilder.getFontManager().setCacheFile(new URI(fopcacheFilePath));

   log.Info("...fop cache set");

   FopFactory fopFactory = fopFactoryBuilder.build();
   FOUserAgent userAgent = fopFactory.newFOUserAgent();
   userAgent.setRendererOverride(null);
   Fop fop = fopFactory.newFop(MimeConstants.MIME_PDF, userAgent, baos);
   
   fopFactory.newFop(MimeConstants.MIME_PDF, userAgent, baos);

   log.Info("...fop created");

   Source src = getSourceForXML(xml);
   Transformer transformer = getTransformerForXSLBA(xslba);
   transformer.setOutputProperty("encoding", "UTF-8");

   log.Info("...transformer prepared");
   
   Result res = new SAXResult(fop.getDefaultHandler());
   transformer.transform(src, res);
   log.Info("...transformation executed");

   byte[] byteArray = baos.toByteArray();
   bool signpdf = true;
   bool lockpdfwithpassword = true;
   if (signpdf || lockpdfwithpassword)
   {
       MemoryStream ss = new MemoryStream();
       DigiSignPdf(byteArray, ss, new FileStream(homeloc + "/cert/GrECo-TestPDFSigningCertificate-pwd_GrECo-Test.pfx", FileMode.Open), "GrECo-Test", "I love signing", "Somewhere on the cloud", "Sasa Bojanic", signpdf, lockpdfwithpassword ? "enhydra" : null, false);
       byteArray = ss.ToArray();
   }


   var result = req.CreateResponse();
   result.StatusCode = HttpStatusCode.OK;
   result.Content = new ByteArrayContent(byteArray);            
   result.Content.Headers.Add("Content-Type", "application/pdf");

   return result;
   
}

public static Transformer getTransformerForXSLBA(byte[] xslbytes)
{
   Transformer transformer = null;
   if (xslbytes != null)
   {
       InputStream bais = new ByteArrayInputStream(xslbytes);

       TransformerFactory factory = TransformerFactory.newInstance();
       transformer = factory.newTransformer(new StreamSource(bais));
   }
   return transformer;
}

public static Transformer getTransformerForXSL(string xsl) 
{
   Transformer transformer = null;
   if (xsl != null) {
       byte[] bytes = System.Text.Encoding.UTF8.GetBytes(xsl);
       InputStream bais = new ByteArrayInputStream(bytes);
       

       TransformerFactory factory = TransformerFactory.newInstance();
       transformer = factory.newTransformer(new StreamSource(bais));
   }
   return transformer;
}

public static Transformer getTransformerForXSLByPath(string xsl)
{
   Transformer transformer = null;
   if (xsl != null)
   {
       TransformerFactory factory = TransformerFactory.newInstance();
       transformer = factory.newTransformer(new StreamSource(xsl));
   }
   return transformer;
}


public static Source getSourceForXML(string xml)
{
   return new StreamSource(new java.io.StringReader(xml));
}

public static void DigiSignPdf(byte[] source,
       Stream destinationStream,
       Stream privateKeyStream,
       string keyPassword,
       string reason,
       string location,
       string contact,
       bool signPdf,
       string pdfpassword,
       bool isVisibleSignature)
{
   // reader and stamper
   PdfReader reader = new PdfReader(source);
   PdfStamper stamper = null;
   if (signPdf)
   {
       stamper = PdfStamper.CreateSignature(reader, destinationStream, '\0');
   }
   else
   {
       stamper = new PdfStamper(reader, destinationStream);
   }
   // password protection
   if (pdfpassword != null)
   {
       byte[] pwd = Encoding.UTF8.GetBytes(pdfpassword);
       stamper.SetEncryption(pwd, pwd, PdfWriter.AllowPrinting, PdfWriter.ENCRYPTION_AES_128);
   }

   if (signPdf)
   {
       Pkcs12Store pk12 = new Pkcs12Store(privateKeyStream, keyPassword.ToCharArray());
       privateKeyStream.Dispose();

       //then Iterate throught certificate entries to find the private key entry
       string alias = null;
       foreach (string tAlias in pk12.Aliases)
       {
           if (pk12.IsKeyEntry(tAlias))
           {
               alias = tAlias;
               break;
           }
       }
       var pk = pk12.GetKey(alias).Key;


       // appearance
       PdfSignatureAppearance appearance = stamper.SignatureAppearance;
       //appearance.Image = new iTextSharp.text.pdf.PdfImage();
       appearance.Reason = reason;
       appearance.Location = location;
       appearance.Contact = contact;
       if (isVisibleSignature)
       {
           appearance.SetVisibleSignature(new iTextSharp.text.Rectangle(20, 10, 170, 60), reader.NumberOfPages, null);
       }
       // digital signature
       IExternalSignature es = new PrivateKeySignature(pk, "SHA-256");
       MakeSignature.SignDetached(appearance, es, new Org.BouncyCastle.X509.X509Certificate[] { pk12.GetCertificate(alias).Certificate }, null, null, null, 0, CryptoStandard.CMS);
   }
   stamper.Close();
   reader.Close();
   reader.Dispose();
}
