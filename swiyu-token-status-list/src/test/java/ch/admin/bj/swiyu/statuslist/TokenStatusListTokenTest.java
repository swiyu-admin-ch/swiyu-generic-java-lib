package ch.admin.bj.swiyu.statuslist;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

import ch.admin.bj.swiyu.statuslist.dto.TokenStatusListTokenDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class TokenStatusListTokenTest {




    @ParameterizedTest
    @EnumSource(SpecTestVector.class)
    void testSpecTestVectors_thenSuccess(SpecTestVector testVector) {
        var mapper = new ObjectMapper();
        var statusListDto = assertDoesNotThrow(() -> mapper.readValue(testVector.getJsonEncoding(), TokenStatusListTokenDto.TokenStatusListDto.class));
        var bits = statusListDto.getBits();
        var data = statusListDto.getStatusListData();
        var tokenStatusListToken = assertDoesNotThrow(() -> TokenStatusListToken.loadTokenStatusListToken(bits, data));
        var exampleBits = testVector.getExampleBits();
        for (int i = 0; i < Math.pow(2, 20); i++) {
            var status = tokenStatusListToken.getStatus(i);
            assertThat(status).as("Index %d should be as in the test vector".formatted(i)).isEqualTo(exampleBits.getOrDefault(i, 0));
        }
    }

    @Test
    void testCreateNewStatusList_thenSuccess() throws IOException {
        /*
         * Example Data
         * byte_array = [0xc9, 0x44, 0xf9]
         * encoded:
         * {
         * "bits": 2,
         * "lst": "eNo76fITAAPfAgc"
         * }
         */
        // Create an empty token status list like in 9.1 of
        // https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-02.html#name-further-examples
        var statusList = new TokenStatusListToken(2, 12);
        statusList.setStatus(0, 1); // Revoke first entry
        assertEquals(1, statusList.getStatusList()[0]);
        statusList.setStatus(1, 2);
        assertEquals(2, statusList.getStatus(1));
        // First status set is 1, second status bit is 8, both together should be 9
        assertEquals(8 + 1, statusList.getStatusList()[0]);
        /*
         * status[0] = 1
         * status[1] = 2
         * status[2] = 0
         * status[3] = 3
         * status[4] = 0
         * status[5] = 1
         * status[6] = 0
         * status[7] = 1
         * status[8] = 1
         * status[9] = 2
         * status[10] = 3
         * status[11] = 3
         */
        statusList.setStatus(3, 3);
        assertEquals(3, statusList.getStatus(3));
        statusList.setStatus(5, 1);
        assertEquals(1, statusList.getStatus(5));
        statusList.setStatus(6, 2);
        statusList.setStatus(6, 0);
        assertEquals(0, statusList.getStatus(6));
        statusList.setStatus(7, 1);
        statusList.setStatus(8, 1);
        statusList.setStatus(9, 2);
        assertEquals(2, statusList.getStatus(9));
        statusList.setStatus(10, 3);
        statusList.setStatus(11, 3);
        assertThrows(IllegalArgumentException.class, () -> statusList.setStatus(11, 4));
        assertEquals(0xc9, Byte.toUnsignedInt(statusList.getStatusList()[0]));
        assertEquals(0x44, Byte.toUnsignedInt(statusList.getStatusList()[1]));
        assertEquals(0xf9, Byte.toUnsignedInt(statusList.getStatusList()[2]));
        var claims = statusList.getStatusListClaims();
        assertEquals(2, claims.get("bits"));
        // Try loading the one we created
        var statusListLoaded = TokenStatusListToken.loadTokenStatusListToken((int) claims.get("bits"),
                (String) claims.get("lst"), 5);
        for (int i = 0; i < 12; i++) {
            assertEquals(statusList.getStatus(i), statusListLoaded.getStatus(i));
        }
        // Compare to spec lst example
        statusListLoaded = TokenStatusListToken.loadTokenStatusListToken(2, "eNo76fITAAPfAgc", 5);
        for (int i = 0; i < 12; i++) {
            assertEquals(statusList.getStatus(i), statusListLoaded.getStatus(i));
        }
    }

    @Test
    void testLargeStatusList() {
        // Playground for the size of the data
        var entries = (int) (Math.pow(10, 7)); // 10 mio entries
        var statusList = new TokenStatusListToken(2, entries);
        var randomGenerator = new Random();
        for (var i = 0; i < entries * 0.9; i++) { // 90% used randomly (high entropy)
            statusList.setStatus(randomGenerator.nextInt(entries), randomGenerator.nextInt(1, 3));
        }
        var claims = assertDoesNotThrow(statusList::getStatusListClaims);
        // In theory utf-8 => 8 bits, therefore 1 character = 1 byte
        var size_bytes = ((String) claims.get("lst")).length();
        assertTrue(size_bytes < Math.pow(2, 20) * 5);// Smaller than 5MBi to download

    }

    @Test
    void testStatusListStructure() throws IOException {
        var statusList = new TokenStatusListToken(2, 4);
        for (byte statusByte : statusList.getStatusList()) {
            assertEquals(0, statusByte);
        }
        var initialStatusList = statusList.getStatusListData();
        var loadedStatusList = TokenStatusListToken.loadTokenStatusListToken(2, initialStatusList, 5);
        // Should be still the same zipped string after loading
        assertEquals(initialStatusList, loadedStatusList.getStatusListData());
        // Should be still all 0s
        for (byte statusByte : statusList.getStatusList()) {
            assertEquals(0, statusByte);
        }
        statusList.setStatus(0, 3);
        statusList.setStatus(1, 1);
        statusList.setStatus(2, 1);
        statusList.setStatus(3, 2);
        for (byte statusByte : statusList.getStatusList()) {
            assertNotEquals(0, statusByte);
        }
        loadedStatusList = TokenStatusListToken.loadTokenStatusListToken(2, statusList.getStatusListData(), 5);
        assertNotEquals(initialStatusList, loadedStatusList.getStatusListData());
        loadedStatusList.setStatus(0, 0);
        loadedStatusList.setStatus(1, 0);
        loadedStatusList.setStatus(2, 0);
        loadedStatusList.setStatus(3, 0);
        assertEquals(initialStatusList, loadedStatusList.getStatusListData());
        for (byte statusByte : loadedStatusList.getStatusList()) {
            assertEquals(0, statusByte);
        }
        assertThrows(IndexOutOfBoundsException.class, () -> {
            statusList.setStatus(4, 1);
        });
    }
    
    @Test
    void testDecodeStatusList_CompressionBomb_IOExceptionExpected() {
        // Generate a compression bomb
        byte[] compressionBomb = createCompressionBomb(205824); // 201KiB
        // Encode in Base64
        var base64CompressionBomb = Base64.getUrlEncoder().withoutPadding().encodeToString(compressionBomb);
        // Expect an IOException while decompressing
        var exception = assertThrows(IOException.class, () -> {
            TokenStatusListToken.decodeStatusList(base64CompressionBomb, 204800);
        });
        assertThat(exception.getMessage()).startsWith("Decompressed data exceeds safe limit! Possible compression bomb attack.");
    }

    @Test
    void testDecodeStatusList_CompressionBomb_NoExceptionExpected() {
        // Generate a compression bomb
        byte[] compressionBomb = createCompressionBomb(200000); // 200KB
        // Encode in Base64
        var base64CompressionBomb = Base64.getUrlEncoder().withoutPadding().encodeToString(compressionBomb);
        // Expect no IOException while decompressing, because the safe limit is bigger than the compressed data
        assertDoesNotThrow(() -> {
            TokenStatusListToken.decodeStatusList(base64CompressionBomb, 204800);
        });
    }

    /**
     * Creates a highly compressed payload (Compression Bomb) that will exceed the safe limit when decompressed.
     */
    private byte[] createCompressionBomb(int sizeInBytes) {
        try (ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
             // Use deflater with max compression level (9)
             DeflaterOutputStream deflaterStream = new DeflaterOutputStream(byteStream, new Deflater(9))) {

            byte[] largeData = new byte[sizeInBytes];
            Arrays.fill(largeData, (byte) 'A');

            deflaterStream.write(largeData);
            deflaterStream.finish();

            return byteStream.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create compression bomb", e);
        }
    }
}
