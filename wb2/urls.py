from django.urls import path, include
from .views import update_product, update_cart, fetch_categories, fetch_products_by_category, signup, login, add_to_cart,login_or_signup_page,logout_view, view_cart, delete_from_cart, add_category, add_product, checkout, process_payment, payment_done, payment_canceled,toggle_visibility, account, orders
urlpatterns = [
    
    path('', fetch_categories, name='categories'),
    path('categories/<int:category_id>/', fetch_products_by_category, name='category_products'),
    path('signup/', signup, name='signup'),
    path('login/', login, name='login'),
    path('add_to_cart/<int:product_id>/', add_to_cart, name='add_to_cart'),
    path('login-or-signup/', login_or_signup_page, name='login_or_signup_page'),
    path('logout/', logout_view, name='logout'),
    path('view-cart/', view_cart, name='view_cart'),
    path('delete_from_cart/<int:cart_id>/', delete_from_cart, name='delete_from_cart'),
    path('add_category/', add_category, name='add_category'), 
    path('add_product/', add_product, name='add_product'),
    path('checkout/', checkout, name='checkout'),
    path('update_cart/', update_cart, name='update_cart'),
    path('update_product/<int:product_id>/', update_product, name='update_product'),
    path('paypal/', include('paypal.standard.ipn.urls')),
    path('process-payment/', process_payment, name='process_payment'),
    path('payment-done/', payment_done, name='payment_done'),
    path('payment-cancelled/', payment_canceled, name='payment_cancelled'),
    path('toggle_visibility/<int:product_id>/', toggle_visibility, name='toggle_visibility'),
    path('account/', account, name='account'),
    path('orders/', orders, name='orders'),
]