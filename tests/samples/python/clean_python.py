def calculate_total_price(unit_price: float, quantity: int) -> float:
    """Calculates total price including standard tax."""
    if unit_price < 0 or quantity < 0:
        raise ValueError("Price and quantity must be non-negative")
    tax_rate = 0.05
    subtotal = unit_price * quantity
    total_price = subtotal * (1 + tax_rate)
    return round(total_price, 2)
