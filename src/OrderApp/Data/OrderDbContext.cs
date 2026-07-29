namespace OrderApp.Data;

// Minimal stub - the fixture's SQL injection vuln (CODE-02) intentionally
// bypasses EF entirely via raw SqlCommand, so this context is not wired
// into that path. Present only to keep the project shape realistic.
public class OrderDbContext
{
    public string ConnectionString { get; set; } = string.Empty;
}
