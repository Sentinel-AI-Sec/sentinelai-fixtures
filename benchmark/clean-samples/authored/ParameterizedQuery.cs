// Near-miss clean sample (SEC-38 clean-samples).
// RESEMBLES: the flagship CWE-89 SQL injection (UsersController), where user input is
//            concatenated straight into the SQL text.
// WHY IT'S SAFE: the user value is bound as a typed command parameter (@username) and is
//            never concatenated into the command text, so it cannot alter query structure.
using Microsoft.Data.SqlClient;
using System.Data;

namespace CleanSamples;

public static class ParameterizedQuery
{
    public static SqlCommand ByUsername(SqlConnection conn, string username)
    {
        var cmd = new SqlCommand(
            "SELECT Id, Email FROM Users WHERE Username = @username", conn);
        cmd.Parameters.Add(new SqlParameter("@username", SqlDbType.NVarChar, 256)
        {
            Value = username
        });
        return cmd;
    }
}
