import pandas as pd

# Load history file
def load_history():
    return pd.read_csv("history.csv")

# Save any dataframe to CSV
def save_csv(dataframe, filename):
    dataframe.to_csv(filename, index=False)
    print(f"{filename} saved successfully!")