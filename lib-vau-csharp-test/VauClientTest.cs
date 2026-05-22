using System;
using System.Collections;
using System.Net.Http;
using System.Threading.Tasks;

using lib_vau_csharp;

using lib_vau_csharp_test.EpaApiClients.Auth;
using lib_vau_csharp_test.EpaApiClients.EntitlementManagement;

using Mauve.Erezept.API.EpaServiceClients.MedicationService;

using Microsoft.Extensions.DependencyInjection;

using NUnit.Framework;

using VerifyNUnit;

using VerifyTests;

using ErrorType = lib_vau_csharp_test.EpaApiClients.EntitlementManagement.ErrorType;

namespace lib_vau_csharp_test
{
    [Explicit("Needs running epa deployment.")]
    public class VauClientTest
    {
        private VauClient vauClient;

        [OneTimeSetUp]
        public void InitVerifyPdfPig() => VerifyPdfPig.Initialize();

        [SetUp]
        public void Setup()
        {
            var vauClientHttpClient = new HttpClient { BaseAddress = Constants.EpaDeploymentUrl };
            vauClient = new VauClient(vauClientHttpClient);
        }

        [Test]
        public async Task ConnectionIdIsSetAfterHandshake()
        {
            await vauClient.DoHandshake();

            Assert.That(vauClient.ConnectionId, Is.Not.Null);
        }

        [Test]
        public async Task CanGetStatus()
        {
            await vauClient.DoHandshake();
            var vauStatus = await vauClient.GetStatus();

            Assert.That(vauStatus, Is.Not.Null);
        }

        [Test]
        public async Task VauHttpClientHandlerDoesDecryptionAndEncryptionWhenCallingAnApiMethod()
        {
            var vauHttpClientHandler = new VauHttpClientHandler(new ReturnInstanceVauClientProvider(vauClient, true));
            var httpClient = new HttpClient(vauHttpClientHandler) { BaseAddress = Constants.EpaDeploymentUrl };

            var authorizationServiceClient = new AuthorizationServiceClient(httpClient);
            var response = await authorizationServiceClient.GetNonceAsync("Test/1.0");

            Console.WriteLine(response.Nonce);
        }

        [Test]
        public void UsageWithIHttpClientFactory()
        {
            var services = new ServiceCollection();
            services.AddTransient<VauHttpClientHandler>();
            services.AddSingleton<IVauClientProvider, VauClientProviderSingleInstance>();
            services.AddHttpClient("VAU").ConfigurePrimaryHttpMessageHandler<VauHttpClientHandler>();
            services.AddTransient<IEntitlementManagementClient>(sp =>
                                                                {
                                                                    var httpClientFactory = sp.GetService<IHttpClientFactory>();
                                                                    var httpClient = httpClientFactory.CreateClient("VAU");
                                                                    httpClient.BaseAddress = Constants.EpaDeploymentUrl;
                                                                    return ActivatorUtilities.CreateInstance<EntitlementManagementClient>(sp, httpClient);
                                                                });

            var sp = services.BuildServiceProvider();

            var entitlementManagementClient = sp.GetService<IEntitlementManagementClient>();
            var request = new EntitlementRequestType { Jwt = "An invalid JWT" };
            Assert.ThrowsAsync<EntitlementManagementException<ErrorType>>(() => entitlementManagementClient.SetEntitlementPsAsync(request, "Z123456783", "Test/1.0"));
        }

        [Test]
        [TestCaseSource(nameof(ThrowingMethods))]
        public void ThrowsInvalidOperationExceptionIfHandshakeWasNotPerformed(Func<Task> method, string methodName)
        {
            Assert.ThrowsAsync<InvalidOperationException>(() => method(), $"Expected method {methodName} to throw an InvalidOperationException.");
        }

        [Test(Description = "Expects medication data to be imported.")]
        public async Task GetMedicationListPdf()
        {
            var vauHttpClientHandler = new VauHttpClientHandler(new ReturnInstanceVauClientProvider(vauClient, true));
            var httpClient = new HttpClient(vauHttpClientHandler) { BaseAddress = Constants.EpaDeploymentUrl };

            var medicationServiceClient = new MedicationServiceClient(httpClient);

            using FileResponse response = await medicationServiceClient.RenderEMLAsPDFAsync(Guid.NewGuid(), "Z123456783", "Test/1.0");

            await Verifier.Verify(response.Stream, "pdf");
        }

        private static IEnumerable ThrowingMethods()
        {
            var client = new VauClient(new HttpClient());

            yield return new TestCaseData(() => client.DecryptResponse(new HttpResponseMessage()), nameof(client.DecryptResponse));
            yield return new TestCaseData(() => client.EncryptRequest(new HttpRequestMessage { RequestUri = new Uri("https://example.com") }), nameof(client.EncryptRequest));
            yield return new TestCaseData(() => client.GetStatus(), nameof(client.GetStatus));
            yield return new TestCaseData(() => client.SendMessage([]), nameof(client.SendMessage));
        }

        private class ReturnInstanceVauClientProvider(VauClient vauClient, bool doHandshake = false) : IVauClientProvider
        {
            public async Task<VauClient> GetVauClient(Uri uri)
            {
                if (doHandshake)
                    await vauClient.DoHandshake();

                return vauClient;
            }
        }

        private class VauClientProviderSingleInstance(IHttpClientFactory httpClientFactory) : IVauClientProvider
        {
            private VauClient vauClient;

            public async Task<VauClient> GetVauClient(Uri uri)
            {
                if (vauClient != null)
                    return vauClient;

                var httpClient = httpClientFactory.CreateClient();
                httpClient.BaseAddress = new Uri(uri.GetLeftPart(UriPartial.Authority)); //Extract record system url

                vauClient = new VauClient(httpClient);
                await vauClient.DoHandshake();
                return vauClient;
            }
        }
    }
}