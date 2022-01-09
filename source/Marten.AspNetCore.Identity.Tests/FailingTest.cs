using Xunit;

namespace Marten.AspNetCore.Identity.Tests;

public class FailingTest
{
    [Fact]
    public void DoesFail()
    {
        Assert.True(false);
    }
}