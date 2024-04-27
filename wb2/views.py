#rom django.http import HttpResponse
#from django.shortcuts import render
#from django.db import connection
from django.http import JsonResponse
from django.contrib.auth.hashers import make_password, check_password
from django.shortcuts import redirect, render
from django.http import HttpResponse
from django.db import connection
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponseRedirect
from django.urls import reverse
from .models import Category, Cart, Product
from .models import User
from django.contrib.auth import authenticate,login as auth_login, login, logout
from django.contrib import messages
from .settings import PAYPAL_RECEIVER_EMAIL
import json



def signup(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        address = request.POST.get('address')
        phonenumber = request.POST.get('phonenumber')
        hashed_password = make_password(password)


        with connection.cursor() as cursor:
            cursor.execute("SELECT MAX(UserID) FROM users")
            max_id = cursor.fetchone()[0]  # Assuming the UserID is not nullable.
            user_id = max_id + 1 if max_id else 1
            cursor.execute("INSERT INTO users (UserID, Username, Email, Password, Admin, address, phonenumber) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                           [user_id, username, email, hashed_password, False, address, phonenumber ])
        return redirect('login')
    return render(request, 'signup.html')
        


from django.contrib.auth import authenticate, login
from django.shortcuts import redirect



def login(request):
    if request.method == 'POST':   
        username = request.POST.get('username')
        password = request.POST.get('password')

        with connection.cursor() as cursor:
            cursor.execute("SELECT UserID, Password, Admin FROM users WHERE Username = %s", [username])
            user_record = cursor.fetchone()
            if user_record and check_password(password, user_record[1]):
                # Set user session
                request.session['user_id'] = user_record[0]
                request.session['is_admin'] = bool(user_record[2]) 
                return redirect('categories')
            else:
                return HttpResponse("Invalid login", status=401)
    return render(request, 'login.html')


def fetch_categories(request):
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM Categories")
        categories = cursor.fetchall()

    # Check if the user_id is in session to determine if the user is logged in
    user_logged_in = 'user_id' in request.session
    is_admin = request.session.get('is_admin', False) 

    # Pass the user_logged_in flag to the template
    context = {
        'categories': categories,
        'user_logged_in': user_logged_in,
        'is_admin': is_admin
    }
    return render(request, 'categories.html', context)

def add_category(request):
    if 'user_id' not in request.session or not request.session.get('is_admin', False):
        # Redirect non-admin users to the login page or somewhere appropriate
        return redirect('login')

    if request.method == 'POST':
        category_name = request.POST.get('category_name')

        with connection.cursor() as cursor:
            # INSERT statement without specifying 'category' since it should auto-increment
            cursor.execute("INSERT INTO Categories (CategoryName) VALUES (%s)", [category_name])

        # Redirect to the categories page after adding the new category
        return redirect('categories')

    # If it's a GET request or the user is not an admin, just show the add category form
    return render(request, 'categories')

def fetch_products_by_category(request, category_id):
    # Determine if the user is an admin or not.
    is_admin = request.session.get('is_admin', False)
    
    # The SQL query changes depending on the admin status. Admins see all products, while others see only visible products.
    if is_admin:
        query = "SELECT * FROM products WHERE Categories_category = %s"
        params = [category_id]
    else:
        query = "SELECT * FROM products WHERE Categories_category = %s AND is_visible = 1"
        params = [category_id]

    with connection.cursor() as cursor:
        cursor.execute(query, params)
        products = cursor.fetchall()

    return render(request, 'products.html', {
        'products': products,
        'category_id': category_id,
        'is_admin': is_admin
    })


  


from django.http import JsonResponse, HttpResponseBadRequest
from django.db import connection


def add_to_cart(request, product_id):
    print("Session data:", request.session.items())
    if 'user_id' not in request.session:
        # Redirect to a page with links to login or signup
        return HttpResponseRedirect(reverse('login_or_signup_page'))
    
    user_id = request.session['user_id']
    quantity = 1  # Assuming we add one product at a time
    
    with connection.cursor() as cursor:
        # First, check if there is an existing order for the user
        cursor.execute("SELECT order_id FROM cart WHERE Users_UserID = %s LIMIT 1", [user_id])
        order_id_result = cursor.fetchone()
        
        if order_id_result:
            order_id = order_id_result[0]
        else:
            # If there is no existing order, create a new order_id
            cursor.execute("SELECT MAX(order_id) FROM cart")
            max_order_id_result = cursor.fetchone()
            max_order_id = max_order_id_result[0] if max_order_id_result[0] else 0
            order_id = max_order_id + 1
        
        # Check if the product is already in the user's cart
        cursor.execute("SELECT CartID, quantity FROM cart WHERE Users_UserID = %s AND Products_ProductID = %s", [user_id, product_id])
        cart_item = cursor.fetchone()
        
        if cart_item:
            # If the item exists, update the quantity
            new_quantity = cart_item[1] + quantity
            cursor.execute("UPDATE cart SET quantity = %s WHERE CartID = %s", [new_quantity, cart_item[0]])
        else:
            # If the item does not exist, add a new item to the cart
            cursor.execute("INSERT INTO cart (quantity, Users_UserID, Products_ProductID, order_id) VALUES (%s, %s, %s, %s)", [quantity, user_id, product_id, order_id])
            print(f"Product ID {product_id} added to cart with Order ID {order_id}")
    
    # return HttpResponse("Item added to cart.")
    return redirect('view_cart')


def login_or_signup_page(request):
    return render(request, 'login_or_signup.html')

def logout_view(request):
    user_id = request.session.get('user_id')  # Get the user's ID from the session
    print("Logging out user: ", user_id)  # Debug print

    if user_id:
        with connection.cursor() as cursor:
            # Delete all items from the cart for the current user
            cursor.execute("DELETE FROM cart WHERE Users_UserID = %s", [user_id])

    request.session.flush()  # This clears the session, including the user_id
    print("Session keys after flush: ", request.session.keys())  # Should be empty after flush

    return redirect('categories')  # Redirect the user to the categories page or home page after logout



def view_cart(request):
    if 'user_id' not in request.session:
        return redirect('login')
    else:
        user_id = request.session['user_id']
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT c.CartID, c.quantity, p.ProductID, p.description, p.Price
                FROM cart c
                JOIN products p ON c.Products_ProductID = p.ProductID
                WHERE c.Users_UserID = %s
            """, [user_id])
            cart_items = cursor.fetchall()

        cart_items_dicts = [{
            'cart_id': item[0],
            'quantity': item[1],
            'product_id': item[2],
            'description': item[3],
            'price': item[4]
        } for item in cart_items]

        cart_items_json = json.dumps(cart_items_dicts)

        return render(request, 'view_cart.html', {
            'cart_items_json': cart_items_json,
            'cart_items': cart_items_dicts  # Pass this as a list of dicts directly
        })

from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt  # This is for simplicity, consider using CSRF tokens properly in production
@require_POST
def update_cart(request):
    cart_id = request.POST.get('cart_id')
    new_quantity = request.POST.get('quantity')
    if new_quantity.isdigit() and int(new_quantity) > 0:
        with connection.cursor() as cursor:
            cursor.execute("""
                UPDATE cart SET quantity = %s WHERE CartID = %s
            """, [new_quantity, cart_id])
        return JsonResponse({'status': 'success', 'cart_id': cart_id, 'new_quantity': new_quantity})
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid quantity'})

from django.db import transaction


def delete_from_cart(request, cart_id):
    # Check if user is logged in
    if 'user_id' not in request.session:
        return redirect('login')

    user_id = request.session['user_id']
    
    try:
        with connection.cursor() as cursor:
            # Log the action we're about to take for debug purposes
            print(f"Executing delete for user_id: {user_id}, cart_id: {cart_id}")

            # Execute the SQL command, targeting the CartID
            cursor.execute("DELETE FROM cart WHERE Users_UserID = %s AND CartID = %s", [user_id, cart_id])
            
            # Check how many rows were deleted
            print(f"Rows deleted: {cursor.rowcount}")
            
            # More logging for debug purposes
            print(f"Attempted to delete cart_id {cart_id} for user_id {user_id}")
            
        # Return a success response
        #return HttpResponse("Item successfully deleted from cart.")
        return JsonResponse({'status': 'success', 'cart_id': cart_id})
    except Exception as e:
        # Log any errors that occur
        print(f"Error during deletion: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
        #return HttpResponse("An error occurred while trying to delete the item from the cart.", status=500)


def add_product(request):
    # Initialize category_id to None or a default value
    category_id = None

    # If 'category_id' is in request.GET, it means we're trying to add a product to a specific category.
    if 'category_id' in request.GET:
        category_id = request.GET['category_id']

    if 'user_id' not in request.session or not request.session.get('is_admin', False):
        # Redirect non-admin users to the login page
        return redirect('login')

    if request.method == 'POST':
        description = request.POST.get('description')
        price = request.POST.get('price')
        invetory = request.POST.get('invetory')

        category_id = request.POST.get('category_id')

        if not invetory:
            # Handle the case where inventory is not provided
            return HttpResponse("Inventory cannot be empty.", status=400)


        with connection.cursor() as cursor:
            cursor.execute("""
                INSERT INTO products (description, price, invetory, Categories_category)
                VALUES (%s, %s, %s, %s)
            """, [description, price, invetory, category_id])

        # Redirect back to the products page for the given category
        #return redirect('fetch_products_by_category', category_id=category_id)
        return render(request, 'products.html', {
        'products': products,
        'category_id': category_id,
        'is_admin': is_admin
    })

    # Retrieve the list of categories only if we need to display the form
    if request.method == 'GET':
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM categories")
            categories = cursor.fetchall()

        # Return the form for adding a product with the categories
        return render(request, 'add_product.html', {
            'categories': categories,
            'category_id': category_id  # Pass the category ID to the template
        })

def update_product(request, product_id):
    if request.method == 'POST' and 'user_id' in request.session and request.session.get('is_admin', False):
        # Retrieve data from POST request
        description = request.POST.get('description')
        price = request.POST.get('price')
        inventory = request.POST.get('inventory')
        
        updates = []
        params = []

        # Check if the fields are provided and add them to the updates list
        if description:
            updates.append("description = %s")
            params.append(description)
        if price:
            updates.append("price = %s")
            params.append(price)
        if inventory:
            updates.append("inventory = %s")
            params.append(inventory)

        # Execute SQL if there's at least one field to update
        if updates:
            params.append(product_id)
            sql = "UPDATE products SET " + ", ".join(updates) + " WHERE product_id = %s"
            with connection.cursor() as cursor:
                cursor.execute(sql, params)

        return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))

    return HttpResponseRedirect('/')


from paypal.standard.forms import PayPalPaymentsForm




def checkout(request):
    if 'user_id' not in request.session:
        return HttpResponseRedirect(reverse('login'))
    
    user_id = request.session['user_id']
    address = ''  # Initialize address as an empty string

    # Query to fetch the user's address separately
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT address FROM users WHERE UserID = %s
        """, [user_id])
        address_result = cursor.fetchone()
        if address_result:
            address = address_result[0] if address_result[0] else ''

    # Query to fetch cart items
    cart_items_dicts = []
    total_price = 0
    with connection.cursor() as cursor:
        cursor.execute("""
            SELECT c.CartID, c.quantity, c.order_id, p.ProductID, p.description, p.price
            FROM cart c
            JOIN products p ON c.Products_ProductID = p.ProductID
            WHERE c.Users_UserID = %s
        """, [user_id])
        results = cursor.fetchall()

        cart_items_dicts = [{
            'cart_id': item[0],
            'quantity': item[1],
            'order_id': item[2],
            'product_id': item[3],
            'name': item[4],
            'price': item[5]
        } for item in results]

        total_price = sum(item['quantity'] * item['price'] for item in cart_items_dicts) if cart_items_dicts else 0

    # Check for POST request to update address
    if request.method == 'POST':
        new_address = request.POST.get('address', '').strip()
        with connection.cursor() as cursor:
            cursor.execute("UPDATE users SET address = %s WHERE UserID = %s", [new_address, user_id])

        messages.success(request, "Address updated successfully!")
        return redirect('checkout')  # Refresh the page to show updated address

    # PayPal setup remains the same
    paypal_dict = {
        'business': PAYPAL_RECEIVER_EMAIL,
        'amount': '%.2f' % total_price,
        'item_name': 'Order {}'.format(cart_items_dicts[0]['order_id'] if cart_items_dicts else 'N/A'),
        'invoice': str(cart_items_dicts[0]['order_id'] if cart_items_dicts else 'N/A'),
        'currency_code': 'USD',
        'notify_url': 'http://{}{}'.format(request.get_host(), reverse('paypal-ipn')),
        'return_url': 'http://{}{}'.format(request.get_host(), reverse('payment_done')),
        'cancel_return': 'http://{}{}'.format(request.get_host(), reverse('payment_cancelled')),
    }

    form = PayPalPaymentsForm(initial=paypal_dict)

    return render(request, 'process_payment.html', {
        'order_id': cart_items_dicts[0]['order_id'] if cart_items_dicts else None,
        'edit_address': False,
        'form': form,
        'cart_items': cart_items_dicts,
        'total_price': total_price,
        'user_id': user_id,
        'address': address  # Pass the fetched address to the template
    })



def toggle_visibility(request, product_id):
    if 'user_id' not in request.session or not request.session.get('is_admin', False):
        return redirect('login')

    if request.method == 'POST':
        with connection.cursor() as cursor:
            cursor.execute("""
                UPDATE products SET is_visible = NOT is_visible WHERE ProductID= %s
            """, [product_id])

        return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))
    return HttpResponseRedirect('/')



from django import template

register = template.Library()







def process_payment(request):
    order_id = request.session.get('order_id')
    order = get_object_or_404(Order, id=order_id)
    host = request.get_host()

    paypal_dict = {
        'business': settings.PAYPAL_RECEIVER_EMAIL,
        'amount': '%.2f' % order.total_cost().quantize(
            Decimal('.01')),
        'item_name': 'Order {}'.format(order.id),
        'invoice': str(order.id),
        'currency_code': 'USD',
        'notify_url': 'http://{}{}'.format(host,
                                           reverse('paypal-ipn')),
        'return_url': 'http://{}{}'.format(host,
                                           reverse('payment_done')),
        'cancel_return': 'http://{}{}'.format(host,
                                              reverse('payment_cancelled')),
    }

    form = PayPalPaymentsForm(initial=paypal_dict)
    return render(request, 'process_payment.html', {'order': order, 'form': form})

@csrf_exempt
def payment_done(request):
    return render(request, 'payment_done.html')


@csrf_exempt
def payment_canceled(request):
    return render(request, 'payment_cancelled.html')

        