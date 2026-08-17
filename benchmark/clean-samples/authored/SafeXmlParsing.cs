// Near-miss clean sample (SEC-38 clean-samples).
// RESEMBLES: the flagship CWE-611 XXE (ReportsController), where XML is parsed with DTD /
//            external-entity processing enabled.
// WHY IT'S SAFE: DTD processing is prohibited and no XmlResolver is set, so external
//            entities and remote DTDs can never be fetched or expanded.
using System.IO;
using System.Xml;

namespace CleanSamples;

public static class SafeXmlParsing
{
    public static XmlReader Create(Stream input)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersFromEntities = 0,
        };
        return XmlReader.Create(input, settings);
    }
}
