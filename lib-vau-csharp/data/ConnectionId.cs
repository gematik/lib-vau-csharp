﻿/*
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

using System;

namespace lib_vau_csharp.data
{
    public class ConnectionId
    {
        public string Cid { get; private set; }
        public ConnectionId(string cid)
        {
            Cid = cid;
        }

        public static ConnectionId CreateRandom()
        {
            return new ConnectionId((DateTime.Now.Ticks / TimeSpan.TicksPerMillisecond).ToString());
        }
    }

}
