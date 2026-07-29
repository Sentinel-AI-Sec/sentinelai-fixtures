namespace OrderApp.Services;

// Deliberately clean-ish service: a distractor node with no chain-worthy
// vulnerability, so not every code node in the graph is "hot".
public class PricingService
{
    private const decimal DefaultTaxRate = 0.08m;

    public decimal CalculateTotal(decimal subtotal, decimal? taxRateOverride = null)
    {
        var rate = taxRateOverride ?? DefaultTaxRate;
        return Math.Round(subtotal * (1 + rate), 2);
    }
}
