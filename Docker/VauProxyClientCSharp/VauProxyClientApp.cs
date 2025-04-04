/*
 * Copyright 2024 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System.Text;
using System.Web;
using vau_proxy_csharp;

namespace VauProxyClientCSharp
{
    public static class VauProxyClientApp
    {
        private static VauProxyClient? vauClient = null;
        private static string url = "http://localhost:8080/";
        private static string testEndpoint = "test/ping";

        public static async void Run(string targetAddress)
        {
            Console.WriteLine("Started Run.");
            vauClient = new VauProxyClient();
            Console.WriteLine("Calling Handshake.");
            Task<bool> handShakeTask = vauClient.DoHandshake(targetAddress);
            handShakeTask.Wait();
            bool handshakeSucceeded = handShakeTask.Result;
            if (!handshakeSucceeded)
            {
                throw new Exception("Error at Vau Proxy Client when attempting handshake.");
            }
            else
            {
                Console.WriteLine("Handshake succeeded");
            }
            bool statusCheckSucceeded = vauClient.TestVauStatus(targetAddress).Result;
            if (!statusCheckSucceeded)
            {
                throw new Exception("Error at Vau Proxy Client when checking VAU Status.");
            }
            else
            {
                Console.WriteLine("VAU Status check succeeded.");
            }
        }
    }
}
