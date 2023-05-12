﻿using System;
using System.Text.RegularExpressions;

namespace Zibma.RestSharp.Authenticators.Digest
{
    internal class DigestHeader
    {
        public const string NONCE = "nonce";

        public const int NONCE_COUNT = 1;

        public const string QOP = "qop";

        public const string REALM = "realm";

        private static readonly Regex _regex;

        static DigestHeader()
        {
            _regex = new Regex(
                "realm=\"(?<realm>.*?)\"|qop=\"(?<qop>.*?)\"|nonce=\"(?<nonce>.*?)\"|stale=\"(?<stale>.*?)\"|opaque=\"(?<opaque>.*?)\"|domain=\"(?<domain>.*?)\"",
                RegexOptions.IgnoreCase | RegexOptions.Compiled);
        }

        public DigestHeader(string authenticateHeader)
        {
            var matches = _regex.Matches(authenticateHeader);
            foreach (Match m in matches)
            {
                if (!m.Success)
                {
                    continue;
                }

                if (m.Groups[QOP].Success)
                {
                    Qop = m.Groups[QOP].Value;
                }

                if (m.Groups[REALM].Success)
                {
                    Realm = m.Groups[REALM].Value;
                }

                if (m.Groups[NONCE].Success)
                {
                    Nonce = m.Groups[NONCE].Value;
                }
            }

            if (!AllDataCorrectFilled())
            {
                throw new ArgumentException(
                    $"Cannot load all required data from {nameof(authenticateHeader)}. Data: {this}");
            }
        }

        public string Nonce { get; }
        public string Qop { get; }
        public string Realm { get; }

        public override string ToString()
        {
            return $"{nameof(Realm)}=\"{Realm}\"&{nameof(Nonce)}=\"{Nonce}\"&{nameof(Qop)}=\"{Qop}\"";
        }

        private bool AllDataCorrectFilled()
        {
            return !string.IsNullOrWhiteSpace(Nonce)
                   && !string.IsNullOrWhiteSpace(Qop)
                   && !string.IsNullOrWhiteSpace(Realm);
        }
    }
}
