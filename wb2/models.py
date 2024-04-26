from django.db import models
from django.contrib.auth.models import AbstractUser


class User(models.Model):
        
    username = models.CharField(max_length=20)
    email = models.EmailField(max_length=100)
    password = models.CharField(max_length=100)
    address = models.CharField(max_length=100)
    phone_number = models.CharField(max_length=100)
    admin = models.BooleanField()
    class Meta:
        db_table = 'users' 
    def __str__(self):
        return self.username

class Category(models.Model):
    category_name = models.CharField(max_length=100)

    def __str__(self):
        return self.category_name

class Product(models.Model):
    description = models.CharField(max_length=100)
    price = models.IntegerField()
    inventory = models.IntegerField()
    category = models.ForeignKey(Category, on_delete=models.CASCADE, related_name='products')

    def __str__(self):
        return self.description

class Cart(models.Model):
    quantity = models.IntegerField()
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.user.username} - {self.product.description} - {self.quantity}"

class Payment(models.Model):
    date = models.DateField()
    amount = models.IntegerField()
    method = models.IntegerField()  # Consider changing to CharField if you want to store method names
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.user.username} - {self.date} - {self.amount}"

class Order(models.Model):
    date = models.DateField()
    total_price = models.IntegerField()
    payment = models.ForeignKey(Payment, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    cart = models.ForeignKey(Cart, on_delete=models.CASCADE)

    def __str__(self):
        return f"Order {self.id} - {self.user.username} - {self.total_price}"
