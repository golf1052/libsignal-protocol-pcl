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

namespace libsignal.devices
{
    public class DeviceConsistencySignature
    {
        private byte[] serialized;

        public DeviceConsistencySignature(byte[] serialized)
        {
            this.serialized = serialized;
        }

        public byte[] getRevealBytes()
        {
            byte[] reveal = new byte[32];
            Buffer.BlockCopy(serialized, 0, reveal, 0, reveal.Length);
            return reveal;
        }

        public byte[] toByteArray()
        {
            return serialized;
        }
    }
}
