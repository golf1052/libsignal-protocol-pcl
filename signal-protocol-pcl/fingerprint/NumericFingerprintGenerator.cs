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

using libsignal;
using libsignal.util;
using PCLCrypto;
using System;
using System.Diagnostics;
using System.Text;
using static PCLCrypto.WinRTCrypto;
using System.Collections.Generic;

namespace org.whispersystems.libsignal.fingerprint
{

    public class NumericFingerprintGenerator : FingerprintGenerator
    {
        private readonly int iterations;

        /**
         * Construct a fingerprint generator for 60 digit numerics.
         *
         * @param iterations The number of internal iterations to perform in the process of
         *                   generating a fingerprint. This needs to be constant, and synchronized
         *                   across all clients.
         *
         *                   The higher the iteration count, the higher the security level:
         *
         *                   - 1024 ~ 109.7 bits
         *                   - 1400 > 110 bits
         *                   - 5200 > 112 bits
         */
        public NumericFingerprintGenerator(int iterations)
        {
            this.iterations = iterations;
        }

        public object MessageDigest { get; private set; }

        /**
         * Generate a scannable and displayble fingerprint.
         *
         * @param localStableIdentifier The client's "stable" identifier.
         * @param localIdentityKey The client's identity key.
         * @param remoteStableIdentifier The remote party's "stable" identifier.
         * @param remoteIdentityKey The remote party's identity key.
         * @return A unique fingerprint for this conversation.
         */

        public Fingerprint createFor(string localStableIdentifier, IdentityKey localIdentityKey,
                               string remoteStableIdentifier, IdentityKey remoteIdentityKey)
        {
            DisplayableFingerprint displayableFingerprint = new DisplayableFingerprint(iterations,
                localStableIdentifier,
                localIdentityKey,
                remoteStableIdentifier,
                remoteIdentityKey);

            ScannableFingerprint scannableFingerprint = new ScannableFingerprint(localStableIdentifier, localIdentityKey,
                                                                                 remoteStableIdentifier, remoteIdentityKey);

            return new Fingerprint(displayableFingerprint, scannableFingerprint);
        }

        /**
        * Generate a scannable and displayble fingerprint for logical identities that have multiple
        * physical keys.
        *
        * Do not trust the output of this unless you've been through the device consistency process
        * for the provided localIdentityKeys.
        *
        * @param localStableIdentifier The client's "stable" identifier.
        * @param localIdentityKeys The client's collection of physical identity keys.
        * @param remoteStableIdentifier The remote party's "stable" identifier.
        * @param remoteIdentityKeys The remote party's collection of physical identity key.
        * @return A unique fingerprint for this conversation.
        */
        public Fingerprint createFor(string localStableIdentifier, List<IdentityKey> localIdentityKeys,
            string remoteStableIdentifier, List<IdentityKey> remoteIdentityKeys)
        {
            DisplayableFingerprint displayableFingerprint = new DisplayableFingerprint(iterations,
                localStableIdentifier,
                localIdentityKeys,
                remoteStableIdentifier,
                remoteIdentityKeys);

            ScannableFingerprint scannableFingerprint = new ScannableFingerprint(localStableIdentifier, localIdentityKeys,
                remoteStableIdentifier, remoteIdentityKeys);

            return new Fingerprint(displayableFingerprint, scannableFingerprint);
        }
    }

}