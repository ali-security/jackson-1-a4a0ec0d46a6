package org.codehaus.jackson.map.jsontype;

import java.util.List;

import org.codehaus.jackson.annotate.JsonTypeInfo;
import org.codehaus.jackson.map.BaseMapTest;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;

/**
 * Regression test for CVE-2019-10202: with default typing enabled, Jackson must
 * refuse to deserialize known dangerous "gadget" classes, and generic class-name
 * type ids must be assignment-compatible with the declared base type.
 *
 * <p>With {@code DefaultTyping.NON_FINAL} the wire format for a polymorphic
 * value read as {@code Object} is a WRAPPER_ARRAY: {@code ["<fqcn>", <value>]}.
 * That is exactly the shape of the published exploit payloads.
 */
public class TestPolymorphicDeserGadgetBlocking
    extends BaseMapTest
{
    @JsonTypeInfo(use=JsonTypeInfo.Id.CLASS, include=JsonTypeInfo.As.WRAPPER_ARRAY)
    static abstract class Base { }

    static class Impl extends Base {
        public int x;
    }

    static class Holder {
        public Base value;
    }

    private ObjectMapper defaultTypingMapper()
    {
        ObjectMapper mapper = new ObjectMapper();
        mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
        return mapper;
    }

    public void testGadgetClassIsBlocked() throws Exception
    {
        ObjectMapper mapper = defaultTypingMapper();

        final String gadget = "com.sun.rowset.JdbcRowSetImpl";
        String json = "[\"" + gadget + "\",{\"dataSourceName\":\"ldap://127.0.0.1:1389/a\",\"autoCommit\":true}]";

        try {
            mapper.readValue(json, Object.class);
            fail("Should not have deserialized blocklisted gadget class " + gadget);
        } catch (JsonMappingException e) {
            verifyException(e, "prevented for security reasons");
        }
    }

    public void testSecondGadgetClassIsBlocked() throws Exception
    {
        ObjectMapper mapper = defaultTypingMapper();

        final String gadget = "java.util.logging.FileHandler";
        String json = "[\"" + gadget + "\",{}]";

        try {
            mapper.readValue(json, Object.class);
            fail("Should not have deserialized blocklisted gadget class " + gadget);
        } catch (JsonMappingException e) {
            verifyException(e, "prevented for security reasons");
        }
    }

    public void testLegitimateBeanStillWorks() throws Exception
    {
        ObjectMapper mapper = defaultTypingMapper();

        Object[] input = new Object[] { "hello" };
        String json = mapper.writeValueAsString(input);
        Object[] result = mapper.readValue(json, Object[].class);
        assertEquals(1, result.length);
        assertEquals("hello", result[0]);
    }

    /**
     * A generic class-name type id that is not a subtype of the declared
     * base type must be rejected by ClassNameIdResolver.
     */
    public void testGenericTypeIdMustBeSubtype() throws Exception
    {
        ObjectMapper mapper = new ObjectMapper();
        String json = "{\"value\":[\"java.util.ArrayList<java.lang.String>\",[\"a\"]]}";
        try {
            mapper.readValue(json, Holder.class);
            fail("Should not have accepted non-subtype generic type id");
        } catch (Exception e) {
            verifyException(e, "not subtype of");
        }
    }

    public void testGenericTypeIdSubtypeStillWorks() throws Exception
    {
        ObjectMapper mapper = defaultTypingMapper();
        String json = "[\"java.util.ArrayList<java.lang.String>\",[\"a\"]]";
        Object result = mapper.readValue(json, Object.class);
        assertTrue(result instanceof List<?>);
        assertEquals(1, ((List<?>) result).size());

        Holder h = new ObjectMapper().readValue(
                "{\"value\":[\"" + Impl.class.getName() + "\",{\"x\":3}]}", Holder.class);
        assertEquals(3, ((Impl) h.value).x);
    }
}
