# Logout Process Documentation

## 1. Logout from Current Device
To log out from the current device, the user simply needs to remove the token from local storage.

## 2. Logout from All Devices
### Overview
When a user wants to log out from all devices, we employ a database field called `logoutPin`. This pin is used to validate tokens during the refresh process.

### How It Works
1. **Token Creation**:
    - During sign-in, a `logoutPin` is generated and stored in the database.
    - This `logoutPin` is included in both the access token (optional) and refresh token (mandatory).

2. **Token Validation**:
    - When the user requests a new access token and refresh token, we validate the `logoutPin` present in the refresh token against the one stored in the database.
    - If the pins match, the token is considered valid. If they do not match, the refresh token is deemed invalid, and the user will not receive new tokens.

3. **Logging Out**:
    - To log out from all devices, the user calls the `logout-all` API.
    - This API updates the `logoutPin` in the database, invalidating all existing refresh tokens.

### Considerations
- **Delayed Effect**: One drawback of this approach is that the logout functionality will not take effect immediately. Users may still have valid access tokens until they expire.
- **Alternative Approach**:
    - An alternative (less efficient) method is to validate the `logoutPin` in the access token strategy.
    - However, this can lead to database bottlenecks, as each protected API call would require fetching the `logoutPin` from the database. This method may be suitable for small projects but not for larger systems.

