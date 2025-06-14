using System;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.ServiceModel;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Serialization;
using SatAuthService; // Asegúrate que este using sea correcto

namespace SatMasivaCs
{
    class Program
    {
        // --- CONFIGURACIÓN ---
        private const string MI_RFC = "AAA9999044X2";
        private const string RUTA_PFX = @"D:\Users\usuario25\FIEL_administracion\00001000000701.pfx";
        private const string CONTRASENA_PFX = "Desde_1010";
		//contacto@tangentemexico.com


        //id="d4af731f-88f7-459a-ae4b-8b4e74978adc"

        static async Task Main(string[] args)
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            Console.WriteLine("--- INICIANDO PROCESO COMPLETO DE DESCARGA MASIVA SAT (C#) ---");

            // --- OBTENER TOKEN (USANDO EL MÉTODO WCF QUE YA FUNCIONABA) ---
            var token = await ObtenerTokenAutenticacionAsync(RUTA_PFX, CONTRASENA_PFX);
            if (string.IsNullOrEmpty(token))
            {
                Console.WriteLine("\nNo se pudo obtener el token de autenticación. Abortando proceso.");
                Console.ReadKey();
                return;
            }
            Console.WriteLine($"Token de autenticación obtenido exitosamente.\n");

            // --- SOLICITUD DE DESCARGA CON FIRMA (MÉTODO MANUAL Y CORRECTO) ---
            //await SolicitaDescargaRecibidosAsync(token, RUTA_PFX, CONTRASENA_PFX);
            //await SolicitaDescargaEmitidosAsync(token,  RUTA_PFX, CONTRASENA_PFX);


            string IdSolicitud = "7ce3faa6-e3a4-ab6d-999d215900d3";
            IdSolicitud = "d4af731f-88f7-459a-8b4e74978adc";
            //await SolicitaDescargaFolioAsync(token, IdSolicitud, RUTA_PFX, CONTRASENA_PFX);
            await VerificaSolicitudDescargaAsync(token, IdSolicitud, RUTA_PFX, CONTRASENA_PFX);

            Console.WriteLine("\nProceso finalizado. Presiona una tecla para salir.");
            Console.ReadKey();
        }

        static async Task SolicitaDescargaRecibidosAsync(string token, string pfxPath, string pfxPassword)
        {
            Console.WriteLine("--- Iniciando solicitud de descarga de Recibidos (CON FIRMA) ---");

            X509Certificate2 certificate;
            try
            {
                certificate = new X509Certificate2(pfxPath, pfxPassword, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error al cargar el certificado PFX: {ex.Message}");
                return;
            }

            var fechaInicio = DateTime.Now.AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ss");
            var fechaFin = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss");

            var doc = new XmlDocument { PreserveWhitespace = true };
            // El namespace 'des' no es necesario aquí, ya que el OuterXml lo incluirá del padre.
            var solicitudNode = doc.CreateElement("solicitud");
            solicitudNode.SetAttribute("RfcReceptor", MI_RFC);
            solicitudNode.SetAttribute("RfcSolicitante", MI_RFC);
            solicitudNode.SetAttribute("FechaInicial", fechaInicio);
            solicitudNode.SetAttribute("FechaFinal", fechaFin);
            solicitudNode.SetAttribute("TipoSolicitud", "CFDI");
            solicitudNode.SetAttribute("EstadoComprobante", "Vigente");
            doc.AppendChild(solicitudNode);

            var signedXml = new SignedXml(doc) { SigningKey = certificate.GetRSAPrivateKey() };
            var reference = new Reference { Uri = "" };
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            signedXml.AddReference(reference);

            var keyInfo = new KeyInfo();
            var keyInfoData = new KeyInfoX509Data(certificate);
            keyInfo.AddClause(keyInfoData);
            signedXml.KeyInfo = keyInfo;

            signedXml.ComputeSignature();
            solicitudNode.AppendChild(signedXml.GetXml());

            string soapXml = $@"<s:Envelope xmlns:s=""http://schemas.xmlsoap.org/soap/envelope/"">
                                  <s:Body>
                                    <SolicitaDescargaRecibidos xmlns=""http://DescargaMasivaTerceros.sat.gob.mx"">
                                      {solicitudNode.OuterXml}
                                    </SolicitaDescargaRecibidos>
                                  </s:Body>
                                </s:Envelope>";

            var handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true; // Para el error NameMismatch

            using (var httpClient = new HttpClient(handler))
            {
                var url = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/SolicitaDescargaService.svc";
                var soapAction = "http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescargaRecibidos";

                using (var requestMessage = new HttpRequestMessage(HttpMethod.Post, url))
                {
                    requestMessage.Content = new StringContent(soapXml, Encoding.UTF8, "text/xml");
                    requestMessage.Headers.Add("SOAPAction", soapAction);
                    requestMessage.Headers.Add("Authorization", token);

                    try
                    {
                        Console.WriteLine("\n>>> Realizando llamada HTTP FIRMADA al servicio de descarga...");
                        var response = await httpClient.SendAsync(requestMessage);
                        string responseContent = await response.Content.ReadAsStringAsync();

                        Console.WriteLine($"\nRespuesta del servidor (Status: {response.StatusCode})");
                        Console.WriteLine("-------------------------------------------------");
                        Console.WriteLine(responseContent);
                        Console.WriteLine("-------------------------------------------------");

                        if (responseContent.Contains("CodEstatus=\"5000\""))
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine("\n¡ÉXITO TOTAL! La solicitud de descarga fue aceptada.");
                            Console.ResetColor();
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error: {ex.ToString()}");
                    }
                }
            }
        }

        // --- MÉTODO DE AUTENTICACIÓN ORIGINAL Y FUNCIONAL (CON WCF) ---
        static async Task<string> ObtenerTokenAutenticacionAsync(string pfxPath, string pfxPassword)
        {
            Console.WriteLine(">>> OBTENIENDO TOKEN (Método WCF)...");
            X509Certificate2 certificate;
            try
            {
                certificate = new X509Certificate2(pfxPath, pfxPassword, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error al cargar el certificado PFX para autenticación: {ex.Message}");
                return null;
            }

            var securityBinding = new BasicHttpBinding(BasicHttpSecurityMode.TransportWithMessageCredential);
            securityBinding.Security.Message.ClientCredentialType = BasicHttpMessageCredentialType.Certificate;

            var authEndpoint = new EndpointAddress("https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/Autenticacion/Autenticacion.svc");
            var authClient = new AutenticacionClient(securityBinding, authEndpoint);

            authClient.ClientCredentials.ClientCertificate.Certificate = certificate;
            authClient.ClientCredentials.ServiceCertificate.Authentication.CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None;
            authClient.ClientCredentials.ServiceCertificate.Authentication.RevocationMode = X509RevocationMode.NoCheck;

            try
            {
                var tokenResponse = await authClient.AutenticaAsync();
                return $"WRAP access_token=\"{tokenResponse}\"";
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n--- ERROR INESPERADO EN AUTENTICACIÓN ---");
                Console.WriteLine(ex.ToString());
                return null;
            }
        }

        static async Task SolicitaDescargaEmitidosAsync(string token, string pfxPath, string pfxPassword)
        {
            Console.WriteLine("--- Iniciando solicitud de descarga de Emitidos (CON FIRMA) ---");

            X509Certificate2 certificate;
            try
            {
                certificate = new X509Certificate2(pfxPath, pfxPassword, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error al cargar el certificado PFX: {ex.Message}");
                return;
            }

            // --- 1. Crear el XML de la solicitud sin firmar ---
            var fechaInicio = DateTime.Now.ToString("yyyy-MM-01THH:mm:ss");
            var fechaFin = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss");
            var rfcReceptorParaFiltrar = MI_RFC;

            var doc = new XmlDocument { PreserveWhitespace = true };
            var solicitudNode = doc.CreateElement("solicitud");

            // Atributos de la solicitud de Emitidos
            solicitudNode.SetAttribute("RfcEmisor", MI_RFC); // Ahora usamos RfcEmisor
            solicitudNode.SetAttribute("FechaInicial", fechaInicio);
            solicitudNode.SetAttribute("FechaFinal", fechaFin);
            solicitudNode.SetAttribute("TipoSolicitud", "CFDI");
            // Otros atributos opcionales como EstadoComprobante, TipoComprobante, etc.
            // solicitudNode.SetAttribute("EstadoComprobante", "Vigente");

            // --- Elemento hijo <RfcReceptores> ---
            var rfcReceptoresNode = doc.CreateElement("RfcReceptores");
            var rfcReceptorNode = doc.CreateElement("RfcReceptor");
            rfcReceptorNode.InnerText = rfcReceptorParaFiltrar;
            rfcReceptoresNode.AppendChild(rfcReceptorNode);
            // Puedes añadir más nodos <RfcReceptor> aquí si lo necesitas

            solicitudNode.AppendChild(rfcReceptoresNode); // Añadir la lista de receptores a la solicitud
            doc.AppendChild(solicitudNode);

            // --- 2. Firmar el nodo <solicitud> (Lógica idéntica a la anterior) ---
            var signedXml = new SignedXml(doc) { SigningKey = certificate.GetRSAPrivateKey() };
            var reference = new Reference { Uri = "" };
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            signedXml.AddReference(reference);

            var keyInfo = new KeyInfo();
            var keyInfoData = new KeyInfoX509Data(certificate);
            keyInfo.AddClause(keyInfoData);
            signedXml.KeyInfo = keyInfo;

            signedXml.ComputeSignature();
            solicitudNode.AppendChild(signedXml.GetXml());

            // --- 3. Construir el sobre SOAP final ---
            string soapXml = $@"<s:Envelope xmlns:s=""http://schemas.xmlsoap.org/soap/envelope/"">
                          <s:Body>
                            <SolicitaDescargaEmitidos xmlns=""http://DescargaMasivaTerceros.sat.gob.mx"">
                              {solicitudNode.OuterXml}
                            </SolicitaDescargaEmitidos>
                          </s:Body>
                        </s:Envelope>";

            // --- 4. Enviar la petición con HttpClient ---
            var handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;

            using (var httpClient = new HttpClient(handler))
            {
                var url = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/SolicitaDescargaService.svc";
                var soapAction = "http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescargaEmitidos"; // <-- CAMBIO AQUÍ

                using (var requestMessage = new HttpRequestMessage(HttpMethod.Post, url))
                {
                    requestMessage.Content = new StringContent(soapXml, Encoding.UTF8, "text/xml");
                    requestMessage.Headers.Add("SOAPAction", soapAction);
                    requestMessage.Headers.Add("Authorization", token);

                    try
                    {
                        Console.WriteLine("\n>>> Realizando llamada HTTP FIRMADA al servicio de descarga (Emitidos)...");
                        var response = await httpClient.SendAsync(requestMessage);
                        string responseContent = await response.Content.ReadAsStringAsync();

                        Console.WriteLine($"\nRespuesta del servidor (Status: {response.StatusCode})");
                        Console.WriteLine("-------------------------------------------------");
                        Console.WriteLine(responseContent);
                        Console.WriteLine("-------------------------------------------------");

                        if (responseContent.Contains("CodEstatus=\"5000\""))
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine("\n¡ÉXITO! La solicitud de descarga de Emitidos fue aceptada.");
                            Console.ResetColor();
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error: {ex.ToString()}");
                    }
                }
            }
        }

        static async Task SolicitaDescargaFolioAsync(string token, string folioFiscal, string pfxPath, string pfxPassword)
        {
            Console.WriteLine($"--- Iniciando solicitud de descarga por Folio: {folioFiscal} ---");

            X509Certificate2 certificate;
            try
            {
                certificate = new X509Certificate2(pfxPath, pfxPassword, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error al cargar el certificado PFX: {ex.Message}");
                return;
            }

            // --- 1. Crear el XML de la solicitud sin firmar ---
            var doc = new XmlDocument { PreserveWhitespace = true };
            var solicitudNode = doc.CreateElement("solicitud");

            // Atributos de la solicitud de Folio
            solicitudNode.SetAttribute("RfcSolicitante", MI_RFC); // Buena práctica incluirlo
            solicitudNode.SetAttribute("Folio", folioFiscal); // El UUID de la factura

            doc.AppendChild(solicitudNode);

            // --- 2. Firmar el nodo <solicitud> (Lógica idéntica a las anteriores) ---
            var signedXml = new SignedXml(doc) { SigningKey = certificate.GetRSAPrivateKey() };
            var reference = new Reference { Uri = "" };
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            signedXml.AddReference(reference);

            var keyInfo = new KeyInfo();
            var keyInfoData = new KeyInfoX509Data(certificate);
            keyInfo.AddClause(keyInfoData);
            signedXml.KeyInfo = keyInfo;

            signedXml.ComputeSignature();
            solicitudNode.AppendChild(signedXml.GetXml());

            // --- 3. Construir el sobre SOAP final ---
            string soapXml = $@"<s:Envelope xmlns:s=""http://schemas.xmlsoap.org/soap/envelope/"">
                          <s:Body>
                            <SolicitaDescargaFolio xmlns=""http://DescargaMasivaTerceros.sat.gob.mx"">
                              {solicitudNode.OuterXml}
                            </SolicitaDescargaFolio>
                          </s:Body>
                        </s:Envelope>";

            // --- 4. Enviar la petición con HttpClient ---
            var handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;

            using (var httpClient = new HttpClient(handler))
            {
                var url = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/SolicitaDescargaService.svc";
                var soapAction = "http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescargaFolio"; // <-- CAMBIO AQUÍ

                using (var requestMessage = new HttpRequestMessage(HttpMethod.Post, url))
                {
                    requestMessage.Content = new StringContent(soapXml, Encoding.UTF8, "text/xml");
                    requestMessage.Headers.Add("SOAPAction", soapAction);
                    requestMessage.Headers.Add("Authorization", token);

                    try
                    {
                        Console.WriteLine("\n>>> Realizando llamada HTTP FIRMADA al servicio de descarga (por Folio)...");
                        var response = await httpClient.SendAsync(requestMessage);
                        string responseContent = await response.Content.ReadAsStringAsync();

                        if (response.IsSuccessStatusCode) {
                            // --- DESERIALIZACIÓN DEL XML A OBJETO ---

                            // 1. Cargar la respuesta XML en un XmlDocument para navegarla fácilmente.
                            var xmlDoc = new XmlDocument();
                            xmlDoc.LoadXml(responseContent);

                            // 2. Extraer el nodo que nos interesa deserializar (el ...Result).
                            // Creamos un XmlNamespaceManager para manejar el namespace 's'.
                            var nsmgr = new XmlNamespaceManager(xmlDoc.NameTable);
                            nsmgr.AddNamespace("s", "http://schemas.xmlsoap.org/soap/envelope/");
                            nsmgr.AddNamespace("des", "http://DescargaMasivaTerceros.sat.gob.mx");

                            var resultNode = xmlDoc.SelectSingleNode("//des:SolicitaDescargaFolioResult", nsmgr);

                            if (resultNode != null)
                            {
                                // 3. Crear el serializador y deserializar el nodo a nuestro objeto.
                                var serializer = new XmlSerializer(typeof(SolicitudResult), new XmlRootAttribute("SolicitaDescargaFolioResult") { Namespace = "http://DescargaMasivaTerceros.sat.gob.mx" });

                                using (var reader = new StringReader(resultNode.OuterXml))
                                {
                                    var solicitudResult = (SolicitudResult)serializer.Deserialize(reader);

                                    // 4. Ahora puedes usar el objeto de forma limpia y segura.
                                    Console.WriteLine("\n--- DATOS DE LA RESPUESTA (Objeto) ---");
                                    Console.WriteLine($"ID de Solicitud: {solicitudResult.IdSolicitud}");
                                    Console.WriteLine($"RFC Solicitante: {solicitudResult.RfcSolicitante}");
                                    Console.WriteLine($"Código de Estatus: {solicitudResult.CodEstatus}");
                                    Console.WriteLine($"Mensaje: {solicitudResult.Mensaje}");

                                    if (solicitudResult.CodEstatus == "5000")
                                    {
                                        Console.ForegroundColor = ConsoleColor.Green;
                                        Console.WriteLine("\n¡ÉXITO! La solicitud de descarga por Folio fue aceptada.");
                                        Console.ResetColor();
                                    }
                                    else
                                    {
                                        Console.ForegroundColor = ConsoleColor.Yellow;
                                        Console.WriteLine($"\nADVERTENCIA: La solicitud fue procesada con un estado: {solicitudResult.Mensaje}");
                                        Console.ResetColor();
                                    }
                                }
                            }
                            else
                            {
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine("\nERROR: No se encontró el nodo 'SolicitaDescargaFolioResult' en la respuesta.");
                                Console.ResetColor();
                            }

                        }


                        Console.WriteLine($"\nRespuesta del servidor (Status: {response.StatusCode})");
                        Console.WriteLine("-------------------------------------------------");
                        Console.WriteLine(responseContent);
                        Console.WriteLine("-------------------------------------------------");

                        if (responseContent.Contains("CodEstatus=\"5000\""))
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine("\n¡ÉXITO! La solicitud de descarga por Folio fue aceptada.");
                            Console.ResetColor();
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error: {ex.ToString()}");
                    }
                }
            }
        }



        static async Task VerificaSolicitudDescargaAsync(string token, string idSolicitud, string pfxPath, string pfxPassword)
        {
            Console.WriteLine($"\n--- Verificando estado de la solicitud: {idSolicitud} ---");

            X509Certificate2 certificate;
            try
            {
                certificate = new X509Certificate2(pfxPath, pfxPassword, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error al cargar el certificado PFX: {ex.Message}");
                return;
            }

            // --- 1. Crear el XML de la solicitud sin firmar ---
            var doc = new XmlDocument { PreserveWhitespace = true };
            var solicitudNode = doc.CreateElement("solicitud");

            // Atributos de la solicitud de verificación
            solicitudNode.SetAttribute("RfcSolicitante", MI_RFC);
            solicitudNode.SetAttribute("IdSolicitud", idSolicitud);

            doc.AppendChild(solicitudNode);

            // --- 2. Firmar el nodo <solicitud> ---
            var signedXml = new SignedXml(doc) { SigningKey = certificate.GetRSAPrivateKey() };
            var reference = new Reference { Uri = "" };
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            signedXml.AddReference(reference);

            var keyInfo = new KeyInfo();
            var keyInfoData = new KeyInfoX509Data(certificate);
            keyInfo.AddClause(keyInfoData);
            signedXml.KeyInfo = keyInfo;

            signedXml.ComputeSignature();
            solicitudNode.AppendChild(signedXml.GetXml());

            // --- 3. Construir el sobre SOAP final ---
            string soapXml = $@"<s:Envelope xmlns:s=""http://schemas.xmlsoap.org/soap/envelope/"">
                          <s:Body>
                            <VerificaSolicitudDescarga xmlns=""http://DescargaMasivaTerceros.sat.gob.mx"">
                              {solicitudNode.OuterXml}
                            </VerificaSolicitudDescarga>
                          </s:Body>
                        </s:Envelope>";

            // --- 4. Enviar la petición con HttpClient ---
            var handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;

            using (var httpClient = new HttpClient(handler))
            {
                // OJO: La URL del servicio es diferente
                var url = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/VerificaSolicitudDescargaService.svc";
                var soapAction = "http://DescargaMasivaTerceros.sat.gob.mx/IVerificaSolicitudDescargaService/VerificaSolicitudDescarga";

                using (var requestMessage = new HttpRequestMessage(HttpMethod.Post, url))
                {
                    requestMessage.Content = new StringContent(soapXml, Encoding.UTF8, "text/xml");
                    requestMessage.Headers.Add("SOAPAction", soapAction);
                    requestMessage.Headers.Add("Authorization", token);

                    try
                    {
                        Console.WriteLine("\n>>> Realizando llamada HTTP FIRMADA al servicio de verificación...");
                        var response = await httpClient.SendAsync(requestMessage);
                        string responseContent = await response.Content.ReadAsStringAsync();


                        Console.WriteLine($"\nRespuesta del servidor (Status: {response.StatusCode})");
                        Console.WriteLine("-------------------------------------------------");
                        Console.WriteLine(responseContent);
                        Console.WriteLine("-------------------------------------------------");

                        // Aquí podrías deserializar la respuesta para manejar los diferentes estados:
                        // EstadoSolicitud: 1 (Aceptada), 2 (En Proceso), 3 (Terminada), 4 (Error), 5 (Rechazada), 6 (Vencida)
                        // CodEstatus: 5002 (Solicitud en proceso), 5004 (Descarga terminada), etc.

                        if (response.IsSuccessStatusCode)
                        {
                            // --- DESERIALIZACIÓN DEL XML A OBJETO (MÉTODO MEJORADO) ---
                            var xmlDoc = new XmlDocument();
                            xmlDoc.LoadXml(responseContent);

                            var nsmgr = new XmlNamespaceManager(xmlDoc.NameTable);
                            nsmgr.AddNamespace("s", "http://schemas.xmlsoap.org/soap/envelope/");

                            // Apuntamos al nodo <VerificaSolicitudDescargaResponse> dentro del Body
                            var responseNode = xmlDoc.SelectSingleNode("/s:Envelope/s:Body/*[1]", nsmgr);

                            if (responseNode != null)
                            {
                                // Ahora deserializamos el objeto 'VerificaSolicitudDescargaResponse' completo
                                var serializer = new XmlSerializer(typeof(VerificaSolicitudDescargaResponse));

                                using (var reader = new StringReader(responseNode.OuterXml))
                                {
                                    var verificacionResponse = (VerificaSolicitudDescargaResponse)serializer.Deserialize(reader);

                                    // Accedemos al resultado a través de la propiedad .Result
                                    var verificacionResult = verificacionResponse.Result;

                                    if (verificacionResult != null)
                                    {
                                        // --- Mostrar los resultados de forma estructurada ---
                                        Console.WriteLine("\n--- ESTADO DE LA SOLICITUD (Objeto) ---");
                                        Console.WriteLine($"Estado: {verificacionResult.EstadoSolicitud} ({verificacionResult.Mensaje})");
                                        // ... (el resto de la lógica para mostrar los resultados es idéntica)
                                    }
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error: {ex.ToString()}");
                    }
                }
            }
        }




        static async Task DescargarPaqueteAsync(string token, string idPaquete, string pfxPath, string pfxPassword)
        {
            Console.WriteLine($"\n--- Descargando paquete: {idPaquete} ---");

            X509Certificate2 certificate;
            try
            {
                certificate = new X509Certificate2(pfxPath, pfxPassword, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error al cargar el certificado PFX: {ex.Message}");
                return;
            }

            // --- 1. Crear el XML de la solicitud sin firmar ---
            var doc = new XmlDocument { PreserveWhitespace = true };
            var peticionNode = doc.CreateElement("peticionDescarga");

            peticionNode.SetAttribute("RfcSolicitante", MI_RFC);
            peticionNode.SetAttribute("IdPaquete", idPaquete);

            doc.AppendChild(peticionNode);

            // --- 2. Firmar el nodo ---
            var signedXml = new SignedXml(doc) { SigningKey = certificate.GetRSAPrivateKey() };
            var reference = new Reference { Uri = "" };
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            signedXml.AddReference(reference);

            var keyInfo = new KeyInfo();
            var keyInfoData = new KeyInfoX509Data(certificate);
            keyInfo.AddClause(keyInfoData);
            signedXml.KeyInfo = keyInfo;

            signedXml.ComputeSignature();
            peticionNode.AppendChild(signedXml.GetXml());

            // --- 3. Construir el sobre SOAP final ---
            string soapXml = $@"<s:Envelope xmlns:s=""http://schemas.xmlsoap.org/soap/envelope/"">
                          <s:Body>
                            <PeticionDescargaMasivaTercerosEntrada xmlns=""http://DescargaMasivaTerceros.sat.gob.mx"">
                              {peticionNode.OuterXml}
                            </PeticionDescargaMasivaTercerosEntrada>
                          </s:Body>
                        </s:Envelope>";

            // --- 4. Enviar la petición y guardar la respuesta ---
            var handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;

            using (var httpClient = new HttpClient(handler))
            {
                var url = "https://cfdidescargamasiva.clouda.sat.gob.mx/DescargaMasivaService.svc";
                var soapAction = "http://DescargaMasivaTerceros.sat.gob.mx/IDescargaMasivaTercerosService/Descargar";

                using (var requestMessage = new HttpRequestMessage(HttpMethod.Post, url))
                {
                    requestMessage.Content = new StringContent(soapXml, Encoding.UTF8, "text/xml");
                    requestMessage.Headers.Add("SOAPAction", soapAction);
                    requestMessage.Headers.Add("Authorization", token);

                    try
                    {
                        Console.WriteLine("\n>>> Realizando llamada HTTP FIRMADA al servicio de descarga final...");
                        var response = await httpClient.SendAsync(requestMessage);

                        Console.WriteLine($"\nRespuesta del servidor (Status: {response.StatusCode})");

                        if (response.IsSuccessStatusCode)
                        {
                            // La respuesta es el archivo ZIP, lo leemos como un array de bytes
                            byte[] zipBytes = await response.Content.ReadAsByteArrayAsync();

                            // Guardamos los bytes en un archivo local
                            string filePath = Path.Combine(Environment.CurrentDirectory, $"{idPaquete}.zip");
                            File.WriteAllBytes(filePath, zipBytes);

                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"\n¡ÉXITO! Paquete descargado y guardado en: {filePath}");
                            Console.ResetColor();
                        }
                        else
                        {
                            // Si hay un error, el SAT responde con un XML de Fault
                            string errorContent = await response.Content.ReadAsStringAsync();
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine("\nERROR al descargar el paquete:");
                            Console.WriteLine(errorContent);
                            Console.ResetColor();
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error: {ex.ToString()}");
                    }
                }
            }
        }


    }





    // Esta es la clase principal que representa la respuesta completa.
    // El namespace debe coincidir con el del XML de respuesta.
    [XmlRoot("SolicitaDescargaFolioResponse", Namespace = "http://DescargaMasivaTerceros.sat.gob.mx")]
    public class RespuestaSolicitudDescarga
    {
        // Esta propiedad contendrá el objeto con los datos que nos interesan.
        [XmlElement("SolicitaDescargaFolioResult")]
        public SolicitudResult Result { get; set; }
    }

    // Esta clase representa el nodo <...Result> que contiene los atributos.
    public class SolicitudResult
    {
        // Cada atributo del XML se mapea a una propiedad de la clase.
        [XmlAttribute("IdSolicitud")]
        public string IdSolicitud { get; set; }

        [XmlAttribute("RfcSolicitante")]
        public string RfcSolicitante { get; set; }

        [XmlAttribute("CodEstatus")]
        public string CodEstatus { get; set; }

        [XmlAttribute("Mensaje")]
        public string Mensaje { get; set; }
    }


// Esta es la clase que representa el nodo raíz de la respuesta <VerificaSolicitudDescargaResponse>
// que viene dentro del <s:Body>
[XmlRoot("VerificaSolicitudDescargaResponse", Namespace = "http://DescargaMasivaTerceros.sat.gob.mx")]
    public class VerificaSolicitudDescargaResponse
    {
        // Esta propiedad contiene el objeto con los datos que nos interesan.
        [XmlElement("VerificaSolicitudDescargaResult")]
        public RespuestaVerificacion Result { get; set; }
    }

    // Y aquí está la clase RespuestaVerificacion que te proporcioné antes,
    // que representa el nodo <VerificaSolicitudDescargaResult> con todos sus atributos y elementos.
    // Si ya la tienes, no necesitas añadirla de nuevo. Si no, aquí está completa:

    [XmlRoot("VerificaSolicitudDescargaResult", Namespace = "http://DescargaMasivaTerceros.sat.gob.mx")]
    public class RespuestaVerificacion
    {
        [XmlAttribute("EstadoSolicitud")]
        public string EstadoSolicitud { get; set; }

        [XmlAttribute("CodigoEstadoSolicitud")]
        public string CodigoEstadoSolicitud { get; set; }

        [XmlAttribute("NumeroCFDIs")]
        public string NumeroCFDIs { get; set; }

        [XmlAttribute("CodEstatus")]
        public string CodEstatus { get; set; }

        [XmlAttribute("Mensaje")]
        public string Mensaje { get; set; }

        [XmlElement("IdsPaquetes")]
        public ListaPaquetes IdsPaquetes { get; set; }
    }

    public class ListaPaquetes
    {
        [XmlElement("string", Namespace = "http://schemas.microsoft.com/2003/10/Serialization/Arrays")]
        public List<string> IdPaquete { get; set; }

        public ListaPaquetes()
        {
            IdPaquete = new List<string>();
        }
    }
}