from django import forms

class GoalForm(forms.Form):
    Date = forms.DateField(widget=forms.TextInput(attrs={'class': 'datepicker'}))

    CUD = forms.CharField(max_length=200) 
    Shift_1 = forms.FloatField() 
    Shift_2 = forms.FloatField()
    TB_Goal = forms.FloatField() 
    CU_Goal = forms.FloatField() 
    WH_Goal = forms.FloatField() 
    Scrap_4_Goal = forms.FloatField() 
    Scrap_1_4_Goal_pct = forms.FloatField() 
    Scrap_1_Goal_pct = forms.FloatField() 
    Scrap_2_Goal_pct = forms.FloatField() 
    Scrap_3_Goal_pct = forms.FloatField() 
    Scrap_4_Goal_pct = forms.FloatField() 
