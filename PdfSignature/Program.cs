using System;
using System.Collections.Generic;
using System.IO;
using iText.Forms;
using iText.Kernel.Geom;
using iText.Kernel.Pdf;
using iText.Kernel.Pdf.Annot;
using iText.Signatures;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;

/**
 * Code copied from
 * https://kb.itextpdf.com/home/it7kb/examples/digital-signatures-chapter-5#Digitalsignatures-chapter5-c5_01_signatureintegrity
*/

namespace PdfSignature
{
    class Program
    {
        static void Main(string[] args)
        {
            Program program = new Program();
            string workingDirectory = Environment.CurrentDirectory;
            string[] files = Directory.GetFiles(workingDirectory, "*.pdf", SearchOption.AllDirectories);
            foreach (string file in files)
            {
                program.InspectSignatures(file);
            }
        }

        public SignaturePermissions InspectSignature(PdfDocument pdfDoc, SignatureUtil signUtil, PdfAcroForm form,
            String name, SignaturePermissions perms)
        {
            IList<PdfWidgetAnnotation> widgets = form.GetField(name).GetWidgets();

            // Check the visibility of the signature annotation
            if (widgets != null && widgets.Count > 0)
            {
                Rectangle pos = widgets[0].GetRectangle().ToRectangle();
                int pageNum = pdfDoc.GetPageNumber(widgets[0].GetPage());
                int numberOfPages = pdfDoc.GetNumberOfPages();

                if (pos.GetWidth() == 0 || pos.GetHeight() == 0)
                {
                    Console.Out.WriteLine("Invisible signature");
                }
                else
                {
                    Console.Out.WriteLine(String.Format("Field on page {0} out of {1}; left: {2}, bottom: {3}, right: {4}; top: {5}",
                        pageNum, numberOfPages, pos.GetLeft(), pos.GetBottom(), pos.GetRight(), pos.GetTop()));
                }
            }

            /* Find out how the message digest of the PDF bytes was created,
             * how these bytes and additional attributes were signed
             * and how the signed bytes are stored in the PDF
             */
            PdfPKCS7 pkcs7 = VerifySignature(signUtil, name);
            Console.Out.WriteLine("Digest algorithm: " + pkcs7.GetHashAlgorithm());
            Console.Out.WriteLine("Encryption algorithm: " + pkcs7.GetEncryptionAlgorithm());
            Console.Out.WriteLine("Filter subtype: " + pkcs7.GetFilterSubtype());

            // Get the signing certificate to find out the name of the signer.
            X509Certificate cert = (X509Certificate)pkcs7.GetSigningCertificate();

            ShowCertificateInfo(cert, pkcs7.GetSignDate());

            Console.Out.WriteLine("Name of the signer: "
                                  + CertificateInfo.GetSubjectFields(cert).GetField("CN"));
            if (pkcs7.GetSignName() != null)
            {
                Console.Out.WriteLine("Alternative name of the signer: " + pkcs7.GetSignName());
            }



            /* Get the signing time.
             * Mind that the getSignDate() method is not that secure as timestamp
             * because it's based only on signature author claim. I.e. this value can only be trusted
             * if signature is trusted and it cannot be used for signature verification.
             */
            Console.Out.WriteLine("Signed on: " + pkcs7.GetSignDate().ToUniversalTime().ToString("yyyy-MM-dd"));

            /* If a timestamp was applied, retrieve information about it.
             * Timestamp is a secure source of signature creation time,
             * because it's based on Time Stamping Authority service.
             */
            if (TimestampConstants.UNDEFINED_TIMESTAMP_DATE != pkcs7.GetTimeStampDate())
            {
                Console.Out.WriteLine("TimeStamp: " +
                                      pkcs7.GetTimeStampDate().ToUniversalTime().ToString("yyyy-MM-dd"));
                TimeStampToken ts = pkcs7.GetTimeStampToken();
                Console.Out.WriteLine("TimeStamp service: " + ts.TimeStampInfo.Tsa);
                Console.Out.WriteLine("Timestamp verified? " + pkcs7.VerifyTimestampImprint());
            }

            Console.Out.WriteLine("Location: " + pkcs7.GetLocation());
            Console.Out.WriteLine("Reason: " + pkcs7.GetReason());
            Console.Out.WriteLine("Timestamp date: " + pkcs7.GetTimeStampDate());
            Console.Out.WriteLine("Timestamp token: " + pkcs7.GetTimeStampToken());
            Console.Out.WriteLine("Timestamp verified? " + pkcs7.VerifyTimestampImprint());

            /* If you want less common entries than PdfPKCS7 object has, such as the contact info,
             * you should use the signature dictionary and get the properties by name.
             */
            PdfDictionary sigDict = signUtil.GetSignatureDictionary(name);
            PdfString contact = sigDict.GetAsString(PdfName.ContactInfo);
            if (contact != null)
            {
                Console.Out.WriteLine("Contact info: " + contact);
            }

            /* Every new signature can add more restrictions to a document, but it can’t take away previous restrictions.
             * So if you want to retrieve information about signatures restrictions, you need to pass
             * the SignaturePermissions instance of the previous signature, or null if there was none.
             */
            perms = new SignaturePermissions(sigDict, perms);
            Console.Out.WriteLine("Signature type: " + (perms.IsCertification() ? "certification" : "approval"));
            Console.Out.WriteLine("Filling out fields allowed: " + perms.IsFillInAllowed());
            Console.Out.WriteLine("Adding annotations allowed: " + perms.IsAnnotationsAllowed());
            foreach (SignaturePermissions.FieldLock Lock in perms.GetFieldLocks())
            {
                Console.Out.WriteLine("Lock: " + Lock);
            }

            return perms;
        }

        public PdfPKCS7 VerifySignature(SignatureUtil signUtil, String name)
        {
            PdfPKCS7 pkcs7 = signUtil.ReadSignatureData(name);

            Console.Out.WriteLine("Signature covers whole document: " + signUtil.SignatureCoversWholeDocument(name));
            Console.Out.WriteLine("Document revision: " + signUtil.GetRevision(name) + " of "
                                  + signUtil.GetTotalRevisions());
            Console.Out.WriteLine("Integrity check OK? " + pkcs7.VerifySignatureIntegrityAndAuthenticity());
            return pkcs7;
        }

        public virtual void InspectSignatures(String path)
        {
            Console.WriteLine("\n\n");
            PdfDocument pdfDoc = new PdfDocument(new PdfReader(path));
            PdfAcroForm form = PdfAcroForm.GetAcroForm(pdfDoc, false);
            SignaturePermissions perms = null;
            SignatureUtil signUtil = new SignatureUtil(pdfDoc);
            IList<String> names = signUtil.GetSignatureNames();

            Console.WriteLine(path);
            foreach (String name in names)
            {
                Console.Out.WriteLine("===== " + name + " =====");
                perms = InspectSignature(pdfDoc, signUtil, form, name, perms);
            }
            PdfAConformanceLevel conformanceLevel = pdfDoc.GetReader().GetPdfAConformanceLevel();
            string conformance = conformanceLevel == null ? string.Empty : conformanceLevel.GetConformance();
            string part = conformanceLevel == null ? string.Empty : conformanceLevel.GetPart();
            Console.Out.WriteLine($"Document conformance: {conformance}/{part}");
            GetMetaInfo(pdfDoc);
        }

        public void ShowCertificateInfo(X509Certificate cert, DateTime signDate)
        {
            Console.WriteLine("Issuer: " + cert.IssuerDN);
            Console.WriteLine("Subject: " + cert.SubjectDN);
            Console.WriteLine("Valid from: " + cert.NotBefore.ToUniversalTime().ToString("yyyy-MM-dd"));
            Console.WriteLine("Valid to: " + cert.NotAfter.ToUniversalTime().ToString("yyyy-MM-dd"));

            // Check if a certificate was valid on the signing date
            try
            {
                cert.CheckValidity(signDate);
                Console.WriteLine("The certificate was valid at the time of signing.");
            }
            catch (CertificateExpiredException)
            {
                Console.WriteLine("The certificate was expired at the time of signing.");
            }
            catch (CertificateNotYetValidException)
            {
                Console.WriteLine("The certificate wasn't valid yet at the time of signing.");
            }

            // Check if a certificate is still valid now
            try
            {
                cert.CheckValidity();
                Console.WriteLine("The certificate is still valid.");
            }
            catch (CertificateExpiredException)
            {
                Console.WriteLine("The certificate has expired.");
            }
            catch (CertificateNotYetValidException)
            {
                Console.WriteLine("The certificate isn't valid yet.");
            }
        }

        public static void GetMetaInfo(PdfDocument pdfDocument)
        {
            var pdfTrailer = pdfDocument.GetTrailer();
            var pdfDictInfo = pdfTrailer.GetAsDictionary(PdfName.Info);
            foreach (var pdfEntryPair in pdfDictInfo.EntrySet())
            {
                string key = pdfEntryPair.Key.ToString();
                string value;
                switch (pdfEntryPair.Value)
                {
                    case PdfString pdfString:
                        value = pdfString.ToUnicodeString();
                        break;
                    default:
                        value = pdfEntryPair.Value.ToString();
                        break;
                }
                Console.WriteLine($"---Meta--- {key} - {value}");
            }
        }
    }
}
