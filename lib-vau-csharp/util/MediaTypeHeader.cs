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

using System.Net.Http.Headers;
using System.Net.Mime;

namespace lib_vau_csharp.util
{
    internal static class MediaTypeHeader
    {
        public static readonly MediaTypeWithQualityHeaderValue Cbor = new MediaTypeWithQualityHeaderValue("application/cbor");
        public static readonly MediaTypeWithQualityHeaderValue Octet = new MediaTypeWithQualityHeaderValue(MediaTypeNames.Application.Octet);
    }
}