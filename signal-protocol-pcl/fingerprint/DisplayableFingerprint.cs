/** 
* Copyright (C) 2017 smndtrl, langboost, golf1052
* 
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using libsignal;
using libsignal.util;
using PCLCrypto;
using static PCLCrypto.WinRTCrypto;

namespace org.whispersystems.libsignal.fingerprint
{
    public class DisplayableFingerprint : BaseFingerprintType
    {
        private static readonly int VERSION = 0;

        private readonly string localFingerprint;
        private readonly string remoteFingerprint;

        internal DisplayableFingerprint(int iterations,
            string localStableIdentifier, IdentityKey localIdentityKey,
            string remoteStableIdentifier, IdentityKey remoteIdentityKey) :
            this(iterations, localStableIdentifier,
                new List<IdentityKey>(new[]
                {
                    localIdentityKey
                }),
                remoteStableIdentifier,
                new List<IdentityKey>(new[]
                {
                    remoteIdentityKey
                }))
        {
        }

        internal DisplayableFingerprint(int iterations,
            string localStableIdentifier, List<IdentityKey> localIdentityKeys,
            string remoteStableIdentifier, List<IdentityKey> remoteIdentityKeys)
        {
            this.localFingerprint = getDisplayStringFor(iterations, localStableIdentifier, localIdentityKeys);
            this.remoteFingerprint = getDisplayStringFor(iterations, remoteStableIdentifier, remoteIdentityKeys);
        }

        public string getDisplayText()
        {
            if (localFingerprint.CompareTo(remoteFingerprint) <= 0)
            {
                return localFingerprint + remoteFingerprint;
            }
            else
            {
                return remoteFingerprint + localFingerprint;
            }
        }

        private string getDisplayStringFor(int iterations, string stableIdentifier, List<IdentityKey> unsortedIdentityKeys)
        {
            try
            {
                List<IdentityKey> sortedIdentityKeys = new List<IdentityKey>(unsortedIdentityKeys);
                sortedIdentityKeys.Sort(new IdentityKeyComparator());

                IHashAlgorithmProvider digest = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha512);
                byte[] publicKey = getLogicalKeyBytes(sortedIdentityKeys);
                byte[] hash = ByteUtil.combine(ByteUtil.shortToByteArray(VERSION),
                    publicKey, Encoding.UTF8.GetBytes(stableIdentifier));

                for (int i = 0; i < iterations; i++)
                {
                    hash = digest.HashData(ByteUtil.combine(new byte[][] { hash, publicKey }));
                }

                return getEncodedChunk(hash, 0) +
                    getEncodedChunk(hash, 5) +
                    getEncodedChunk(hash, 10) +
                    getEncodedChunk(hash, 15) +
                    getEncodedChunk(hash, 20) +
                    getEncodedChunk(hash, 25);
            }
            catch (Exception e)
            {
                Debug.Assert(false, e.Message);
                throw e;
            }
        }

        private string getEncodedChunk(byte[] hash, int offset)
        {
            long chunk = ByteUtil.byteArray5ToLong(hash, offset) % 100000;
            return string.Format("{0:d5}", chunk);
        }
    }
}