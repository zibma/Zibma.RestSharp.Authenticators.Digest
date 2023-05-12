using RestSharp;
using RestSharp.Authenticators;
using System;
using System.Threading.Tasks;

namespace Zibma.RestSharp.Authenticators.Digest
{
    public class DigestAuthenticator : IAuthenticator
    {
        private const int DEFAULT_TIMEOUT = 100000;     // 100000 = 100 sec
        private readonly string _password;

        private readonly string _username;

        /// <summary>
        ///     Creates a new instance of <see cref="DigestAuthenticator" /> class.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <param name="password">The password.</param>
        public DigestAuthenticator(string username, string password)
        {
            _username = username;
            _password = password;
            Timeout = DEFAULT_TIMEOUT;
        }

        /// <summary>
        ///     The web request timeout (default 100000).
        /// </summary>
        public int Timeout { get; set; }

        /// <inheritdoc cref="IAuthenticator" />
        public async ValueTask Authenticate(IRestClient client, RestRequest request)
        {
            Uri uri = client.BuildUri(request);
            var manager = new DigestAuthenticatorManager(client.BuildUri(new RestRequest()), _username, _password, Timeout);
            await manager.FetchDigestAuthHeader(uri.PathAndQuery, request.Method).ConfigureAwait(false);
            string digestHeader = manager.GetDigestHeader(uri.PathAndQuery, request.Method);

            request.AddOrUpdateHeader("Connection", "keep-alive");
            request.AddOrUpdateHeader(KnownHeaders.Authorization, digestHeader);
        }
    }
}
