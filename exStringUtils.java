import java.lang.*;
import java.util.*;
import java.security.SecureRandom;
import org.apache.commons.lang3.RandomStringUtils;

public class PasswordGenerator { 
    public String generateCommonLangPassword() {
        String upperCaseLetters = RandomStringUtils.random(2, 65, 90, true, true, new SecureRandom());
        String lowerCaseLetters = RandomStringUtils.random(2, 97, 122, true, true, new SecureRandom());
        String numbers = RandomStringUtils.randomNumeric(2);
        String specialChar = RandomStringUtils.random(2, 33, 47, false, false, new SecureRandom());
        String totalChars = RandomStringUtils.randomAlphanumeric(2);
        String combinedChars = upperCaseLetters.concat(lowerCaseLetters)
        .concat(numbers)
        .concat(specialChar)
        .concat(totalChars);
        List<Character> pwdChars = combinedChars.chars()
        .mapToObj(c -> (char) c)
        .collect(Collectors.toList());
        Collections.shuffle(pwdChars);
        String password = pwdChars.stream()
        .collect(StringBuilder::new, StringBuilder::append, StringBuilder::append)
        .toString();
        return password;
    }
}