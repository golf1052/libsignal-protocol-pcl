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

using System.Diagnostics;
using Google.ProtocolBuffers;
using libsignal.devices;
using libsignal.ecc;

namespace libsignal.protocol
{
    public class DeviceConsistencyMessage
    {
        private readonly DeviceConsistencySignature signature;
        private readonly byte[] serialized;

        public DeviceConsistencyMessage(DeviceConsistencyCommitment commitment, IdentityKeyPair identityKeyPair)
        {
            try
            {
                this.signature = new DeviceConsistencySignature(Curve.calculateUniqueSignature(identityKeyPair.getPrivateKey(), commitment.toByteArray()));
                this.serialized = SignalProtos.DeviceConsistencyCodeMessage.CreateBuilder()
                    .SetGeneration((uint)commitment.getGeneration())
                    .SetSignature(ByteString.CopyFrom(signature.toByteArray()))
                    .Build()
                    .ToByteArray();
            }
            catch (InvalidKeyException e)
            {
                Debug.Assert(false);
                throw e;
            }
        }

        public DeviceConsistencyMessage(DeviceConsistencyCommitment commitment, byte[] serialized, IdentityKey identityKey)
        {
            try
            {
                SignalProtos.DeviceConsistencyCodeMessage message = SignalProtos.DeviceConsistencyCodeMessage.ParseFrom(serialized);

                if (!Curve.verifyUniqueSignature(identityKey.getPublicKey(), commitment.toByteArray(), message.Signature.ToByteArray()))
                {
                    throw new InvalidMessageException("Bad signature!");
                }

                this.signature = new DeviceConsistencySignature(message.Signature.ToByteArray());
                this.serialized = serialized;
            }
            catch (InvalidProtocolBufferException e)
            {
                throw new InvalidMessageException(e);
            }
            catch (InvalidKeyException e)
            {
                throw new InvalidMessageException(e);
            }
        }

        public byte[] getSerialized()
        {
            return serialized;
        }

        public DeviceConsistencySignature getSignature()
        {
            return signature;
        }
    }
}
