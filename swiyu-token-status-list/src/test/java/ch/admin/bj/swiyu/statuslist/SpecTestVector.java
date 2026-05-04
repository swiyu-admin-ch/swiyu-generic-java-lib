package ch.admin.bj.swiyu.statuslist;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.Map;

/**
 * Test Vectors as defined in
 * <a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-20#appendix-C.1">Token Status List Spec Appendix</a>
 * All examples are initialized with a size of 2^20 entries.
 */
@Getter
@RequiredArgsConstructor
public enum SpecTestVector {

    _1_BIT_EXAMPLE(
            """
                    {
                      "bits": 1,
                      "lst": "eNrt3AENwCAMAEGogklACtKQPg9LugC9k_ACvreiogEAAKkeCQAAAAAAAAAAAAAAAAAAAIBylgQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXG9IAAAAAAAAAPwsJAAAAAAAAAAAAAAAvhsSAAAAAAAAAAAA7KpLAAAAAAAAAAAAAAAAAAAAAJsLCQAAAAAAAAAAADjelAAAAAAAAAAAKjDMAQAAAACAZC8L2AEb"
                    }""",
            Map.ofEntries(
                Map.entry(0, 0b1),
                Map.entry(1993, 0b1),
                Map.entry(25460, 0b1),
                Map.entry(159495, 0b1),
                Map.entry(495669, 0b1),
                Map.entry(554353, 0b1),
                Map.entry(645645, 0b1),
                Map.entry(723232, 0b1),
                Map.entry(854545, 0b1),
                Map.entry(934534, 0b1),
                Map.entry(1000345, 0b1)
            )
    ),
    _2_BIT_EXAMPLE("""
            {
              "bits": 2,
              "lst": "eNrt2zENACEQAEEuoaBABP5VIO01fCjIHTMStt9ovGVIAAAAAABAbiEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEB5WwIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAID0ugQAAAAAAAAAAAAAAAAAQG12SgAAAAAAAAAAAAAAAAAAAAAAAAAAAOCSIQEAAAAAAAAAAAAAAAAAAAAAAAD8ExIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwJEuAQAAAAAAAAAAAAAAAAAAAAAAAMB9SwIAAAAAAAAAAAAAAAAAAACoYUoAAAAAAAAAAAAAAEBqH81gAQw"
            }""",
            Map.ofEntries(
                Map.entry(0, 0b01),
                Map.entry(1993, 0b10),
                Map.entry(25460, 0b01),
                Map.entry(159495, 0b11),
                Map.entry(495669, 0b01),
                Map.entry(554353, 0b01),
                Map.entry(645645, 0b10),
                Map.entry(723232, 0b01),
                Map.entry(854545, 0b01),
                Map.entry(934534, 0b10),
                Map.entry(1000345, 0b11)

            ));

    private final String jsonEncoding;
    private final Map<Integer, Integer> exampleBits;
}
