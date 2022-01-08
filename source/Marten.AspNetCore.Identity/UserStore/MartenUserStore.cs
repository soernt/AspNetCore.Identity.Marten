using System.Security.Claims;
using Marten.AspNetCore.Identity.Extensions;
using Marten.AspNetCore.Identity.Models;
using Marten.Exceptions;
using Microsoft.AspNetCore.Identity;

namespace Marten.AspNetCore.Identity.UserStore;

/// <summary>
/// /// Represents a new instance of a persistence store for the specified user type.
/// </summary>
/// <typeparam name="TUser">The type representing a user.</typeparam>
/// <typeparam name="TRole">The typ representing a role</typeparam>
public class MartenUserStore<TUser, TRole> :
    IQueryableUserStore<TUser>,
    IUserPasswordStore<TUser>,
    IUserRoleStore<TUser>,
    IUserEmailStore<TUser>,
    IUserPhoneNumberStore<TUser>,
    IUserSecurityStampStore<TUser>,
    IUserClaimStore<TUser>,
    IUserLoginStore<TUser>,
    IUserLockoutStore<TUser>,
    IUserTwoFactorStore<TUser>,
    IUserAuthenticationTokenStore<TUser>,
    IUserAuthenticatorKeyStore<TUser>,
    IUserTwoFactorRecoveryCodeStore<TUser>
    where TUser : MartenIdentityUser
    where TRole : MartenIdentityRole
{
    private const string InternalLoginProvider = "[AspNetUserStore]";
    private const string AuthenticatorKeyTokenName = "AuthenticatorKey";

    /// <summary>
    /// True when Disposed is called.
    /// </summary>
    private bool _disposed;

    /// <summary>
    /// The Marten <see cref="IDocumentStore"/>
    /// </summary>
    private readonly IDocumentStore _documentStore;

    /// <summary>
    /// Gets the <see cref="IdentityErrorDescriber"/> for any error that occurred with the current operation.
    /// </summary>
    protected readonly IdentityErrorDescriber ErrorDescriber;

    /// <summary>
    /// Singleton session 
    /// </summary>
    private IDocumentSession? _session;

    /// <summary>
    /// Session used for updating and querying the role store
    /// </summary>
    protected IDocumentSession Session => _session ??= _documentStore.OpenSession(DocumentTracking.None);

    /// <summary>
    /// A navigation property for the users the store contains.
    /// </summary>
    public IQueryable<TUser> Users
    {
        get
        {
            ThrowIfDisposed();
            return Session.Query<TUser>();
        }
    }

    /// <summary>
    /// Constructs a new instance of <see cref="MartenUserStore{TUser,TKey}"/>.
    /// </summary>
    /// <param name="documentStore">The Marten <see cref="IDocumentStore"/>.</param>
    /// <param name="describer">The <see cref="IdentityErrorDescriber"/> used to describe store errors.</param>
    public MartenUserStore(IDocumentStore documentStore, IdentityErrorDescriber? describer = null)
    {
        _documentStore = documentStore ?? throw new ArgumentNullException(nameof(documentStore));
        ErrorDescriber = describer ?? new IdentityErrorDescriber();
    }

    /// <summary>
    /// Dispose the store
    /// </summary>
    public void Dispose()
    {
        _session?.Dispose();
        _session = null;
        _disposed = true;
    }

    /// <summary>
    /// Throws if this class has been disposed.
    /// </summary>
    protected void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(GetType().Name);
        }
    }

    /// <summary>
    /// Converts the provided <paramref name="id"/> to a strongly typed key object.
    /// </summary>
    /// <param name="id">The id to convert.</param>
    /// <returns>An instance of <typeparamref name="Guid"/> representing the provided <paramref name="id"/>.</returns>
    protected Guid ConvertIdFromString(string id)
    {
        return Guid.Parse(id);
    }

    /// <summary>
    /// Converts the provided <paramref name="id"/> to its string representation.
    /// </summary>
    /// <param name="id">The id to convert.</param>
    /// <returns>An <see cref="string"/> representation of the provided <paramref name="id"/>.</returns>
    protected string? ConvertIdToString(Guid id)
    {
        return id.ToString();
    }

    #region IQueryableUserStore

    /// <summary>
    /// Gets the user identifier for the specified <paramref name="user"/>.
    /// </summary>
    /// <param name="user">The user whose identifier should be retrieved.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the identifier for the specified <paramref name="user"/>.</returns>
    public Task<string?> GetUserIdAsync(TUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        return Task.FromResult(ConvertIdToString(user.Id));
    }

    /// <summary>
    /// Gets the user name for the specified <paramref name="user"/>.
    /// </summary>
    /// <param name="user">The user whose name should be retrieved.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the name for the specified <paramref name="user"/>.</returns>
    public Task<string> GetUserNameAsync(TUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        return Task.FromResult(user.UserName);
    }

    /// <summary>
    /// Sets the given <paramref name="userName" /> for the specified <paramref name="user"/>.
    /// </summary>
    /// <param name="user">The user whose name should be set.</param>
    /// <param name="userName">The user name to set.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
    public Task SetUserNameAsync(TUser user, string userName, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        user.UserName = userName;
        return Task.CompletedTask;
    }

    /// <summary>
    /// Gets the normalized user name for the specified <paramref name="user"/>.
    /// </summary>
    /// <param name="user">The user whose normalized name should be retrieved.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the normalized user name for the specified <paramref name="user"/>.</returns>
    public Task<string> GetNormalizedUserNameAsync(TUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        return Task.FromResult(user.NormalizedUserName);
    }

    /// <summary>
    /// Sets the given normalized name for the specified <paramref name="user"/>.
    /// </summary>
    /// <param name="user">The user whose name should be set.</param>
    /// <param name="normalizedName">The normalized name to set.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
    public Task SetNormalizedUserNameAsync(TUser user, string normalizedName,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        user.NormalizedUserName = normalizedName;
        return Task.CompletedTask;
    }

    /// <summary>
    /// Creates the specified <paramref name="user"/> in the user store.
    /// </summary>
    /// <param name="user">The user to create.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the creation operation.</returns>
    public async Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        Session.Insert(user);
        await Session.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        return IdentityResult.Success;
    }

    /// <summary>
    /// Updates the specified <paramref name="user"/> in the user store.
    /// </summary>
    /// <param name="user">The user to update.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the update operation.</returns>
    public async Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        Session.Update(user);
        try
        {
            await Session.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (ConcurrencyException)
        {
            return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
        }

        return IdentityResult.Success;
    }

    /// <summary>
    /// Deletes the specified <paramref name="user"/> from the user store.
    /// </summary>
    /// <param name="user">The user to delete.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the update operation.</returns>
    public async Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        Session.Delete(user);
        try
        {
            await Session.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (ConcurrencyException)
        {
            return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
        }

        return IdentityResult.Success;
    }

    /// <summary>
    /// Finds and returns a user, if any, who has the specified <paramref name="userId"/>.
    /// </summary>
    /// <param name="userId">The user ID to search for.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>
    /// The <see cref="Task"/> that represents the asynchronous operation, containing the user matching the specified <paramref name="userId"/> if it exists.
    /// </returns>
    public async Task<TUser?> FindByIdAsync(string userId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();

        var id = ConvertIdFromString(userId);
        var user = await Session
            .Query<TUser>()
            .SingleOrDefaultAsync(u => u.Id == id, token: cancellationToken)
            .ConfigureAwait(false);
        return user;
    }

    /// <summary>
    /// Finds and returns a user, if any, who has the specified normalized user name.
    /// </summary>
    /// <param name="normalizedUserName">The normalized user name to search for.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>
    /// The <see cref="Task"/> that represents the asynchronous operation, containing the user matching the specified <paramref name="normalizedUserName"/> if it exists.
    /// </returns>
    public async Task<TUser?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();

        var user = await Session
            .Query<TUser>()
            .SingleOrDefaultAsync(u => u.NormalizedUserName == normalizedUserName, token: cancellationToken)
            .ConfigureAwait(false);

        return user;
    }

    #endregion

    #region IUserPasswordStore

    /// <summary>
    /// Sets the password hash for a user.
    /// </summary>
    /// <param name="user">The user to set the password hash for.</param>
    /// <param name="passwordHash">The password hash to set.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
    public Task SetPasswordHashAsync(TUser user, string passwordHash, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        user.PasswordHash = passwordHash;

        return Task.FromResult(user.PasswordHash);
    }

    /// <summary>
    /// Gets the password hash for a user.
    /// </summary>
    /// <param name="user">The user to retrieve the password hash for.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A <see cref="Task{TResult}"/> that contains the password hash for the user.</returns>
    public Task<string?> GetPasswordHashAsync(TUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        return Task.FromResult(user.PasswordHash);
    }

    /// <summary>
    /// Returns a flag indicating if the specified user has a password.
    /// </summary>
    /// <param name="user">The user to retrieve the password hash for.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A <see cref="Task{TResult}"/> containing a flag indicating if the specified user has a password. If the 
    /// user has a password the returned value with be true, otherwise it will be false.</returns>
    public Task<bool> HasPasswordAsync(TUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(user.PasswordHash != null);
    }

    #endregion

    #region IUserRoleStore

    /// <summary>
    /// Adds the given <paramref name="normalizedRoleName"/> to the specified <paramref name="user"/>.
    /// </summary>
    /// <param name="user">The user to add the role to.</param>
    /// <param name="normalizedRoleName">The role to add.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
    public async Task AddToRoleAsync(TUser user, string normalizedRoleName, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        if (string.IsNullOrWhiteSpace(normalizedRoleName))
        {
            throw new ArgumentException(null, nameof(normalizedRoleName));
        }

        var roleEntity = await FindRoleAsync(normalizedRoleName, cancellationToken).ConfigureAwait(false);
        if (roleEntity == null)
        {
            throw new InvalidOperationException($"Role '{normalizedRoleName}' not found.");
        }

        user.Roles.Add(roleEntity);
    }

    private async Task<TRole?> FindRoleAsync(string normalizedRoleName, CancellationToken cancellationToken)
    {
        var role = await Session
            .Query<TRole>()
            .SingleOrDefaultAsync(r => r.NormalizedName == normalizedRoleName, token: cancellationToken)
            .ConfigureAwait(false);

        return role;
    }

    /// <summary>
    /// Removes the given <paramref name="normalizedRoleName"/> from the specified <paramref name="user"/>.
    /// </summary>
    /// <param name="user">The user to remove the role from.</param>
    /// <param name="normalizedRoleName">The role to remove.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
    public Task RemoveFromRoleAsync(TUser user, string normalizedRoleName, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        if (string.IsNullOrWhiteSpace(normalizedRoleName))
        {
            var msg = "Role name can not be empty";
            throw new ArgumentException(msg, nameof(normalizedRoleName));
        }

        var role = user.Roles.SingleOrDefault(r =>
            string.Equals(r.NormalizedName, normalizedRoleName, StringComparison.Ordinal));
        if (role != null)
        {
            user.Roles.Remove(role);
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Retrieves the roles the specified <paramref name="user"/> is a member of.
    /// </summary>
    /// <param name="user">The user whose roles should be retrieved.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A <see cref="Task{TResult}"/> that contains the roles the user is a member of.</returns>
    public Task<IList<string>> GetRolesAsync(TUser user, CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        var roles = user.Roles.Select(r => r.Name).ToList();

        return Task.FromResult<IList<string>>(roles);
    }

    /// <summary>
    /// Returns a flag indicating if the specified user is a member of the give <paramref name="normalizedRoleName"/>.
    /// </summary>
    /// <param name="user">The user whose role membership should be checked.</param>
    /// <param name="normalizedRoleName">The role to check membership of</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A <see cref="Task{TResult}"/> containing a flag indicating if the specified user is a member of the given group. If the
    /// user is a member of the group the returned value with be true, otherwise it will be false.</returns>
    public Task<bool> IsInRoleAsync(TUser user, string normalizedRoleName, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        if (string.IsNullOrWhiteSpace(normalizedRoleName))
        {
            var msg = "Role name can not be empty";
            throw new ArgumentException(msg, nameof(normalizedRoleName));
        }

        var result = user.Roles.Any(r => string.Equals(r.NormalizedName, normalizedRoleName, StringComparison.Ordinal));
        return Task.FromResult(result);
    }

    /// <summary>
    /// Retrieves all users in the specified role.
    /// </summary>
    /// <param name="normalizedRoleName">The role whose users should be retrieved.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>
    /// The <see cref="Task"/> contains a list of users, if any, that are in the specified role.
    /// </returns>
    public async Task<IList<TUser>> GetUsersInRoleAsync(string normalizedRoleName,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (string.IsNullOrEmpty(normalizedRoleName))
        {
            throw new ArgumentNullException(nameof(normalizedRoleName));
        }

        var result = await Session
            .Query<TUser>()
            .Where(u => u.Roles.Any(r => r.NormalizedName == normalizedRoleName))
            .ToListAsync(token: cancellationToken)
            .ConfigureAwait(false);

        return new List<TUser>(result);
    }

    #endregion

    #region IUserEmailStore

    /// <summary>
    /// Sets the <paramref name="email"/> address for a <paramref name="user"/>.
    /// </summary>
    /// <param name="user">The user whose email should be set.</param>
    /// <param name="email">The email to set.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The task object representing the asynchronous operation.</returns>
    public Task SetEmailAsync(TUser user, string email, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        user.EmailAddress = email;
        return Task.CompletedTask;
    }

    /// <summary>
    /// Gets the email address for the specified <paramref name="user"/>.
    /// </summary>
    /// <param name="user">The user whose email should be returned.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The task object containing the results of the asynchronous operation, the email address for the specified <paramref name="user"/>.</returns>
    public Task<string> GetEmailAsync(TUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        return Task.FromResult(user.EmailAddress);
    }

    /// <summary>
    /// Gets a flag indicating whether the email address for the specified <paramref name="user"/> has been verified, true if the email address is verified otherwise
    /// false.
    /// </summary>
    /// <param name="user">The user whose email confirmation status should be returned.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>
    /// The task object containing the results of the asynchronous operation, a flag indicating whether the email address for the specified <paramref name="user"/>
    /// has been confirmed or not.
    /// </returns>
    public Task<bool> GetEmailConfirmedAsync(TUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        return Task.FromResult(user.IsEmailConfirmed);
    }

    /// <summary>
    /// Sets the flag indicating whether the specified <paramref name="user"/>'s email address has been confirmed or not.
    /// </summary>
    /// <param name="user">The user whose email confirmation status should be set.</param>
    /// <param name="confirmed">A flag indicating if the email address has been confirmed, true if the address is confirmed otherwise false.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The task object representing the asynchronous operation.</returns>
    public Task SetEmailConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        user.IsEmailConfirmed = confirmed;
        return Task.CompletedTask;
    }

    /// <summary>
    /// Gets the user, if any, associated with the specified, normalized email address.
    /// </summary>
    /// <param name="normalizedEmail">The normalized email address to return the user for.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>
    /// The task object containing the results of the asynchronous lookup operation, the user if any associated with the specified normalized email address.
    /// </returns>
    public async Task<TUser?> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();

        var user = await Session
            .Query<TUser>()
            .SingleOrDefaultAsync(u => u.NormalizedEmailAddress == normalizedEmail, token: cancellationToken)
            .ConfigureAwait(false);

        return user;
    }

    /// <summary>
    /// Returns the normalized email for the specified <paramref name="user"/>.
    /// </summary>
    /// <param name="user">The user whose email address to retrieve.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>
    /// The task object containing the results of the asynchronous lookup operation, the normalized email address if any associated with the specified user.
    /// </returns>
    public Task<string> GetNormalizedEmailAsync(TUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        return Task.FromResult(user.NormalizedEmailAddress);
    }

    /// <summary>
    /// Sets the normalized email for the specified <paramref name="user"/>.
    /// </summary>
    /// <param name="user">The user whose email address to set.</param>
    /// <param name="normalizedEmail">The normalized email to set for the specified <paramref name="user"/>.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The task object representing the asynchronous operation.</returns>
    public Task SetNormalizedEmailAsync(TUser user, string normalizedEmail, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        user.NormalizedEmailAddress = normalizedEmail;
        return Task.CompletedTask;
    }

    #endregion

    #region IUserPhoneNumberStore

    /// <summary>
    /// Sets the telephone number for the specified <paramref name="user"/>.
    /// </summary>
    /// <param name="user">The user whose telephone number should be set.</param>
    /// <param name="phoneNumber">The telephone number to set.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
    public Task SetPhoneNumberAsync(TUser user, string phoneNumber, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        user.PhoneNumber = phoneNumber;
        return Task.CompletedTask;
    }

    /// <summary>
    /// Gets the telephone number, if any, for the specified <paramref name="user"/>.
    /// </summary>
    /// <param name="user">The user whose telephone number should be retrieved.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the user's telephone number, if any.</returns>
    public Task<string> GetPhoneNumberAsync(TUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        return Task.FromResult(user.PhoneNumber);
    }


    /// <summary>
    /// Gets a flag indicating whether the specified <paramref name="user"/>'s telephone number has been confirmed.
    /// </summary>
    /// <param name="user">The user to return a flag for, indicating whether their telephone number is confirmed.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>
    /// The <see cref="Task"/> that represents the asynchronous operation, returning true if the specified <paramref name="user"/> has a confirmed
    /// telephone number otherwise false.
    /// </returns>
    public Task<bool> GetPhoneNumberConfirmedAsync(TUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        return Task.FromResult(user.IsPhoneNumberConfirmed);
    }

    /// <summary>
    /// Sets a flag indicating if the specified <paramref name="user"/>'s phone number has been confirmed..
    /// </summary>
    /// <param name="user">The user whose telephone number confirmation status should be set.</param>
    /// <param name="confirmed">A flag indicating whether the user's telephone number has been confirmed.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
    public Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        user.IsPhoneNumberConfirmed = confirmed;
        return Task.CompletedTask;
    }

    #endregion

    #region IUserSecurityStampStore

    /// <summary>
    /// Sets the provided security <paramref name="stamp"/> for the specified <paramref name="user"/>.
    /// </summary>
    /// <param name="user">The user whose security stamp should be set.</param>
    /// <param name="stamp">The security stamp to set.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
    public Task SetSecurityStampAsync(TUser user, string stamp, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        if (stamp == null)
        {
            throw new ArgumentNullException(nameof(stamp));
        }

        user.SecurityStamp = stamp;
        return Task.CompletedTask;
    }

    /// <summary>
    /// Get the security stamp for the specified <paramref name="user" />.
    /// </summary>
    /// <param name="user">The user whose security stamp should be set.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the security stamp for the specified <paramref name="user"/>.</returns>
    public Task<string> GetSecurityStampAsync(TUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        return Task.FromResult(user.SecurityStamp);
    }

    #endregion

    #region IUserClaimStore

    /// <summary>
    /// Get the claims associated with the specified <paramref name="user"/> as an asynchronous operation.
    /// </summary>
    /// <param name="user">The user whose claims should be retrieved.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>A <see cref="Task{TResult}"/> that contains the claims granted to a user.</returns>
    public Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        var claims = user.Claims.Select(c => c.ToClaim()).ToList();

        return Task.FromResult<IList<Claim>>(claims);
    }

    /// <summary>
    /// Adds the <paramref name="claims"/> given to the specified <paramref name="user"/>.
    /// </summary>
    /// <param name="user">The user to add the claim to.</param>
    /// <param name="claims">The claim to add to the user.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
    public Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        if (claims == null)
        {
            throw new ArgumentNullException(nameof(claims));
        }

        foreach (var claim in claims)
        {
            user.Claims.Add(claim.ToMartenIdentityClaim());
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Replaces the <paramref name="claim"/> on the specified <paramref name="user"/>, with the <paramref name="newClaim"/>.
    /// </summary>
    /// <param name="user">The user to replace the claim on.</param>
    /// <param name="claim">The claim replace.</param>
    /// <param name="newClaim">The new claim replacing the <paramref name="claim"/>.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
    public Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        if (claim == null)
        {
            throw new ArgumentNullException(nameof(claim));
        }

        if (newClaim == null)
        {
            throw new ArgumentNullException(nameof(newClaim));
        }

        var matchedClaims = user.Claims.Where(uc =>
            string.Equals(uc.Value, claim.Value, StringComparison.Ordinal)
            && string.Equals(uc.Type, claim.Type, StringComparison.Ordinal)
        );
        foreach (var matchedClaim in matchedClaims)
        {
            matchedClaim.Value = newClaim.Value;
            matchedClaim.Type = newClaim.Type;
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Removes the <paramref name="claims"/> given from the specified <paramref name="user"/>.
    /// </summary>
    /// <param name="user">The user to remove the claims from.</param>
    /// <param name="claims">The claim to remove.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
    public Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        if (claims == null)
        {
            throw new ArgumentNullException(nameof(claims));
        }

        foreach (var claim in claims)
        {
            var matchedClaims = user.Claims.Where(uc =>
                string.Equals(uc.Value, claim.Value, StringComparison.Ordinal)
                && string.Equals(uc.Type, claim.Type, StringComparison.Ordinal)
            ).ToList();

            foreach (var c in matchedClaims)
            {
                user.Claims.Remove(c);
            }
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Retrieves all users with the specified claim.
    /// </summary>
    /// <param name="claim">The claim whose users should be retrieved.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>
    /// The <see cref="Task"/> contains a list of users, if any, that contain the specified claim.
    /// </returns>
    public async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (claim == null)
        {
            throw new ArgumentNullException(nameof(claim));
        }

        var users = await Session
            .Query<TUser>()
            .Where(u => u.Claims.Any(c => c.Type == claim.Type && c.Value == claim.Value))
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        return new List<TUser>(users);
    }

    #endregion

    #region IUserLoginStore

    /// <summary>
    /// Adds the <paramref name="login"/> given to the specified <paramref name="user"/>.
    /// </summary>
    /// <param name="user">The user to add the login to.</param>
    /// <param name="login">The login to add to the user.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
    public Task AddLoginAsync(TUser user, UserLoginInfo login, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        if (login == null)
        {
            throw new ArgumentNullException(nameof(login));
        }

        user.Logins.Add(login.ToMartenIdentityUserLogin());
        return Task.FromResult(false);
    }


    /// <summary>
    /// Removes the <paramref name="loginProvider"/> given from the specified <paramref name="user"/>.
    /// </summary>
    /// <param name="user">The user to remove the login from.</param>
    /// <param name="loginProvider">The login to remove from the user.</param>
    /// <param name="providerKey">The key provided by the <paramref name="loginProvider"/> to identify a user.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
    public Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        var login = user.Logins.SingleOrDefault(l =>
            string.Equals(l.LoginProvider, loginProvider, StringComparison.Ordinal)
            && string.Equals(l.ProviderKey, providerKey, StringComparison.Ordinal));

        if (login != null)
        {
            user.Logins.Remove(login);
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Retrieves the associated logins for the specified <param ref="user"/>.
    /// </summary>
    /// <param name="user">The user whose associated logins to retrieve.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>
    /// The <see cref="Task"/> for the asynchronous operation, containing a list of <see cref="UserLoginInfo"/> for the specified <paramref name="user"/>, if any.
    /// </returns>
    public Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        var logins = user.Logins.Select(l => l.ToUserLoginInfo()).ToList();
        return Task.FromResult<IList<UserLoginInfo>>(logins);
    }

    /// <summary>
    /// Retrieves the user associated with the specified login provider and login provider key.
    /// </summary>
    /// <param name="loginProvider">The login provider who provided the <paramref name="providerKey"/>.</param>
    /// <param name="providerKey">The key provided by the <paramref name="loginProvider"/> to identify a user.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>
    /// The <see cref="Task"/> for the asynchronous operation, containing the user, if any which matched the specified login provider and key.
    /// </returns>
    public async Task<TUser?> FindByLoginAsync(string loginProvider, string providerKey,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();

        var user = await Session
            .Query<TUser>()
            .SingleOrDefaultAsync(
                u => u.Logins.Any(
                    l => l.LoginProvider == loginProvider && l.ProviderKey == providerKey
                ),
                cancellationToken)
            .ConfigureAwait(false);

        return user;
    }

    #endregion

    #region IUserLockoutStore

    /// <summary>
    /// Gets the last <see cref="DateTimeOffset"/> a user's last lockout expired, if any.
    /// Any time in the past should be indicates a user is not locked out.
    /// </summary>
    /// <param name="user">The user whose lockout date should be retrieved.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>
    /// A <see cref="Task{TResult}"/> that represents the result of the asynchronous query, a <see cref="DateTimeOffset"/> containing the last time
    /// a user's lockout expired, if any.
    /// </returns>
    public Task<DateTimeOffset?> GetLockoutEndDateAsync(TUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        return Task.FromResult(user.LockoutEndAtUtc);
    }

    /// <summary>
    /// Locks out a user until the specified end date has passed. Setting a end date in the past immediately unlocks a user.
    /// </summary>
    /// <param name="user">The user whose lockout date should be set.</param>
    /// <param name="lockoutEnd">The <see cref="DateTimeOffset"/> after which the <paramref name="user"/>'s lockout should end.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
    public Task SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        user.LockoutEndAtUtc = lockoutEnd;
        return Task.CompletedTask;
    }

    /// <summary>
    /// Records that a failed access has occurred, incrementing the failed access count.
    /// </summary>
    /// <param name="user">The user whose cancellation count should be incremented.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the incremented failed access count.</returns>
    public Task<int> IncrementAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        user.AccessFailedCount++;
        return Task.FromResult(user.AccessFailedCount);
    }

    /// <summary>
    /// Resets a user's failed access count.
    /// </summary>
    /// <param name="user">The user whose failed access count should be reset.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
    /// <remarks>This is typically called after the account is successfully accessed.</remarks>
    public Task ResetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        user.AccessFailedCount = 0;
        return Task.CompletedTask;
    }

    /// <summary>
    /// Retrieves the current failed access count for the specified <paramref name="user"/>..
    /// </summary>
    /// <param name="user">The user whose failed access count should be retrieved.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the failed access count.</returns>
    public Task<int> GetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        return Task.FromResult(user.AccessFailedCount);
    }

    /// <summary>
    /// Retrieves a flag indicating whether user lockout can enabled for the specified user.
    /// </summary>
    /// <param name="user">The user whose ability to be locked out should be returned.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>
    /// The <see cref="Task"/> that represents the asynchronous operation, true if a user can be locked out, otherwise false.
    /// </returns>
    public Task<bool> GetLockoutEnabledAsync(TUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        return Task.FromResult(user.IsLockoutEnabled);
    }

    /// <summary>
    /// Set the flag indicating if the specified <paramref name="user"/> can be locked out..
    /// </summary>
    /// <param name="user">The user whose ability to be locked out should be set.</param>
    /// <param name="enabled">A flag indicating if lock out can be enabled for the specified <paramref name="user"/>.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
    public Task SetLockoutEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        user.IsLockoutEnabled = enabled;
        return Task.CompletedTask;
    }

    #endregion

    #region IUserTwoFactorStore

    /// <summary>
    /// Sets a flag indicating whether the specified <paramref name="user"/> has two factor authentication enabled or not,
    /// as an asynchronous operation.
    /// </summary>
    /// <param name="user">The user whose two factor authentication enabled status should be set.</param>
    /// <param name="enabled">A flag indicating whether the specified <paramref name="user"/> has two factor authentication enabled.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
    public Task SetTwoFactorEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        user.IsTwoFactorEnabled = enabled;
        return Task.CompletedTask;
    }

    /// <summary>
    /// Returns a flag indicating whether the specified <paramref name="user"/> has two factor authentication enabled or not,
    /// as an asynchronous operation.
    /// </summary>
    /// <param name="user">The user whose two factor authentication enabled status should be set.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>
    /// The <see cref="Task"/> that represents the asynchronous operation, containing a flag indicating whether the specified 
    /// <paramref name="user"/> has two factor authentication enabled or not.
    /// </returns>
    public Task<bool> GetTwoFactorEnabledAsync(TUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        return Task.FromResult(user.IsTwoFactorEnabled);
    }

    #endregion

    #region IUserAuthenticationTokenStore

    private static MartenIdentityUserToken? FindUserToken(TUser user, string loginProvider, string name)
    {
        return user.Tokens.SingleOrDefault(t =>
            string.Equals(t.LoginProvider, loginProvider, StringComparison.Ordinal)
            && string.Equals(t.Name, name, StringComparison.Ordinal)
        );
    }

    /// <summary>
    /// Sets the token value for a particular user.
    /// </summary>
    /// <param name="user">The user.</param>
    /// <param name="loginProvider">The authentication provider for the token.</param>
    /// <param name="name">The name of the token.</param>
    /// <param name="value">The value of the token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
    public Task SetTokenAsync(TUser user, string loginProvider, string name, string value,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();

        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        var token = FindUserToken(user, loginProvider, name);
        if (token == null)
        {
            var martenIdentityUserToken = new MartenIdentityUserToken
            {
                LoginProvider = loginProvider,
                Name = name,
                Value = value
            };
            user.Tokens.Add(martenIdentityUserToken);
        }
        else
        {
            token.Value = value;
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Deletes a token for a user.
    /// </summary>
    /// <param name="user">The user.</param>
    /// <param name="loginProvider">The authentication provider for the token.</param>
    /// <param name="name">The name of the token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
    public Task RemoveTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();

        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        var martenIdentityUserToken = FindUserToken(user, loginProvider, name);
        if (martenIdentityUserToken != null)
        {
            user.Tokens.Remove(martenIdentityUserToken);
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Returns the token value.
    /// </summary>
    /// <param name="user">The user.</param>
    /// <param name="loginProvider">The authentication provider for the token.</param>
    /// <param name="name">The name of the token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
    public Task<string?> GetTokenAsync(TUser user, string loginProvider, string name,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();

        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        var martenIdentityUserToken = FindUserToken(user, loginProvider, name);
        return Task.FromResult(martenIdentityUserToken?.Value);
    }

    #endregion

    #region IUserAuthenticatorKeyStore

    /// <summary>
    /// Sets the authenticator key for the specified <paramref name="user"/>.
    /// </summary>
    /// <param name="user">The user whose authenticator key should be set.</param>
    /// <param name="key">The authenticator key to set.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
    public Task SetAuthenticatorKeyAsync(TUser user, string key, CancellationToken cancellationToken)
    {
        return SetTokenAsync(user, InternalLoginProvider, AuthenticatorKeyTokenName, key, cancellationToken);
    }

    /// <summary>
    /// Get the authenticator key for the specified <paramref name="user" />.
    /// </summary>
    /// <param name="user">The user whose security stamp should be set.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the security stamp for the specified <paramref name="user"/>.</returns>
    public Task<string?> GetAuthenticatorKeyAsync(TUser user, CancellationToken cancellationToken)
    {
        return GetTokenAsync(user, InternalLoginProvider, AuthenticatorKeyTokenName, cancellationToken);
    }

    #endregion

    #region IUserTwoFactorRecoveryCodeStore

    /// <summary>
    /// Updates the recovery codes for the user while invalidating any previous recovery codes.
    /// </summary>
    /// <param name="user">The user to store new recovery codes for.</param>
    /// <param name="recoveryCodes">The new recovery codes for the user.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The new recovery codes for the user.</returns>
    public Task ReplaceCodesAsync(TUser user, IEnumerable<string> recoveryCodes, CancellationToken cancellationToken)
    {
        user.RecoveryCodes.Clear();
        foreach (var recoveryCode in recoveryCodes)
        {
            user.RecoveryCodes.Add(new MartenIdentityRecoveryCode(recoveryCode));
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Returns whether a recovery code is valid for a user. Note: recovery codes are only valid
    /// once, and will be invalid after use.
    /// </summary>
    /// <param name="user">The user who owns the recovery code.</param>
    /// <param name="code">The recovery code to use.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>True if the recovery code was found for the user.</returns>
    public Task<bool> RedeemCodeAsync(TUser user, string code, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();

        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        if (code == null)
        {
            throw new ArgumentNullException(nameof(code));
        }

        var martenRecoveryCode = new MartenIdentityRecoveryCode(code);
        if (!user.RecoveryCodes.Contains(martenRecoveryCode))
        {
            return Task.FromResult(false);
        }

        user.RecoveryCodes.Remove(martenRecoveryCode);
        return Task.FromResult(true);
    }

    /// <summary>
    /// Returns how many recovery code are still valid for a user.
    /// </summary>
    /// <param name="user">The user who owns the recovery code.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
    /// <returns>The number of valid recovery codes for the user..</returns>
    public Task<int> CountCodesAsync(TUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();

        if (user == null)
        {
            throw new ArgumentNullException(nameof(user));
        }

        return Task.FromResult(user.RecoveryCodes.Count);
    }

    #endregion
}