using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using System.Text;
using Altium.Auth;
using Xunit;

namespace Altium.Auth.Tests;

public class ActionWaitTransportTests
{
    [Fact]
    public async Task SignIn_ReconnectsWhenTheRequestTimeoutFiresMidPoll()
    {
        var handler = new PollHandler(
            _ => throw new TaskCanceledException("The request was canceled due to the configured HttpClient.Timeout of 100 seconds elapsing."),
            token => Json(200, $"{{\"data\":{{\"code\":\"c\",\"state\":\"{token}\"}}}}"));

        var tokens = await NewClient(handler).SignInAsync();

        Assert.Equal("AT", tokens.AccessToken);
        Assert.Equal(2, handler.Polls);
    }

    [Fact]
    public async Task SignIn_ReconnectsAfterANetworkFailure()
    {
        var handler = new PollHandler(
            _ => throw new HttpRequestException("An error occurred while sending the request."),
            token => Json(200, $"{{\"data\":{{\"code\":\"c\",\"state\":\"{token}\"}}}}"));

        var tokens = await NewClient(handler).SignInAsync();

        Assert.Equal("AT", tokens.AccessToken);
        Assert.Equal(2, handler.Polls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SignIn_FailsFastOnATlsFailure(bool nestedAsOnNetFramework)
    {
        var tls = new AuthenticationException("The remote certificate is invalid according to the validation procedure.");
        Exception inner = nestedAsOnNetFramework
            ? new WebException("Could not establish trust relationship for the SSL/TLS secure channel.", tls)
            : tls;
        var handler = new PollHandler(_ => throw new HttpRequestException("The SSL connection could not be established.", inner));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => NewClient(handler).SignInAsync());

        Assert.Contains("TLS", ex.Message);
        Assert.Equal(1, handler.Polls);
    }

    [Fact]
    public async Task SignIn_StopsWhenTheCallerCancels()
    {
        using var cts = new CancellationTokenSource();
        var handler = new PollHandler(_ =>
        {
            cts.Cancel();
            throw new TaskCanceledException();
        });

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => NewClient(handler).SignInAsync(cts.Token));
        Assert.Equal(1, handler.Polls);
    }

    private static AltiumAuthClient NewClient(PollHandler handler) =>
        new(new HttpClient(handler), new AltiumAuthOptions { ClientId = "c", Scopes = "openid profile" });

    private static HttpResponseMessage Json(int status, string body) =>
        new((HttpStatusCode)status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private sealed class PollHandler(params Func<string, HttpResponseMessage>[] polls) : HttpMessageHandler
    {
        public int Polls { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            if (!request.RequestUri!.ToString().Contains("actionwait"))
                return Json(200, "{\"access_token\":\"AT\",\"token_type\":\"Bearer\"}");

            var body = await request.Content!.ReadAsStringAsync();
            var token = body.Split('"')[3];
            return polls[Math.Min(Polls++, polls.Length - 1)](token);
        }
    }
}
