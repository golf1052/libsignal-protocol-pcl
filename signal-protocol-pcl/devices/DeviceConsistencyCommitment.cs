/** 
 * Copyright (C) 2017 golf1052
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
using libsignal.util;
using PCLCrypto;
using static PCLCrypto.WinRTCrypto;

namespace libsignal.devices
{
    public class DeviceConsistencyCommitment
    {
        private static readonly string VERSION = "DeviceConsistencyCommitment_V0"; 

        private readonly int generation;
        private readonly byte[] serialized;

        public DeviceConsistencyCommitment(int generation, List<IdentityKey> identityKeys)
        {
            try
            {
                List<IdentityKey> sortedIdentityKeys = new List<IdentityKey>(identityKeys);
                sortedIdentityKeys.Sort(new IdentityKeyComparator());

                IHashAlgorithmProvider messageDigest = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithm.Sha512);
                messageDigest.HashData(Encoding.UTF8.GetBytes(VERSION));
                messageDigest.HashData(ByteUtil.intToByteArray(generation));

                foreach (IdentityKey commitment in sortedIdentityKeys)
                {
                    this.serialized = messageDigest.HashData(commitment.getPublicKey().serialize());
                }

                this.generation = generation;
            }
            catch (Exception e)
            {
                Debug.Assert(false, e.Message);
                throw e;
            }
        }

        public byte[] toByteArray()
        {
            return serialized;
        }

        public int getGeneration()
        {
            return generation;
        }
    }

    class IdentityKeyComparator : ByteArrayComparator, IComparer<IdentityKey>
    {
        public int Compare(IdentityKey first, IdentityKey second)
        {
            return compare(first.getPublicKey().serialize(), second.getPublicKey().serialize());
        }
    }
}
