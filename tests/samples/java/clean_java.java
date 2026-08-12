public class CleanCalculator {

    public double calculateInterest(double principal, double rate, int years) {
        if (principal < 0 || rate < 0 || years < 0) {
            throw new IllegalArgumentException("Arguments must be non-negative.");
        }
        return principal * Math.pow(1 + rate, years);
    }
}
