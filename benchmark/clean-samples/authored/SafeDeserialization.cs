// Near-miss clean sample (SEC-38 clean-samples).
// RESEMBLES: the flagship CWE-502 unsafe deserialization (OrdersController, Newtonsoft
//            TypeNameHandling.All), which lets a request pick the CLR type to instantiate.
// WHY IT'S SAFE: deserializes to a fixed, known DTO with System.Text.Json, which does not
//            honor embedded "$type" directives and performs no polymorphic type resolution.
//            No attacker-controlled type can be instantiated.
using System.Text.Json;

namespace CleanSamples;

public record OrderDto(string Product, int Quantity);

public static class SafeDeserialization
{
    public static OrderDto Parse(string json)
    {
        // Fixed target type; no TypeNameHandling, no polymorphic binder.
        return JsonSerializer.Deserialize<OrderDto>(json)
               ?? throw new JsonException("empty payload");
    }
}
