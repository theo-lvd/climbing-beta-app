# We need the 'csv' library to help us work with CSV files.
import csv
import os # This helps us check if the file already exists.

# The name of the file where we will store our betas.
FILENAME = "betas.csv"

def add_beta():
    """Asks the user for beta details and saves them to the file."""
    print("\n--- Add a New Beta ---")
    
    # Ask the user for each piece of information.
    name = input("Enter the boulder/route name: ")
    location = input("Enter the location (e.g., gym or crag): ")
    grade = input("Enter the grade: ")
    beta_desc = input("Enter the beta description: ")
    
    # 'with open(...)' is the safe way to handle files in Python.
    # 'a' means "append" - we add to the end of the file.
    # 'newline=''' is important for the csv library to work correctly.
    with open(FILENAME, mode='a', newline='') as file:
        # Create a writer object to write to our CSV file.
        beta_writer = csv.writer(file)
        
        # Write the new beta as a new row in the file.
        beta_writer.writerow([name, location, grade, beta_desc])
        
    print(f"\n✅ Success! Beta for '{name}' was saved.")

def view_betas():
    """Reads all betas from the file and prints them to the screen."""
    print("\n--- All Your Saved Betas ---")
    
    try:
        with open(FILENAME, mode='r') as file:
            # Create a reader object to read the CSV file.
            beta_reader = csv.reader(file)
            
            # The 'for row in beta_reader:' loop reads one line at a time.
            for row in beta_reader:
                # row is a list, like ['Le Toit d'Orsay', 'Orsay', '7a', '...']
                print(f"\nName:     {row[0]}")
                print(f"Location: {row[1]}")
                print(f"Grade:    {row[2]}")
                print(f"Beta:     {row[3]}")
                print("-" * 20) # Prints a separator line like "--------------------"

    except FileNotFoundError:
        # This message shows if you try to view betas before saving any.
        print("\nNo betas saved yet! Add one first.")

def main():
    """The main function that runs our application menu."""
    
    # Create the file with headers if it doesn't exist.
    # This is a good practice for CSV files.
    if not os.path.exists(FILENAME):
        with open(FILENAME, mode='w', newline='') as file:
            writer = csv.writer(file)
            # This is the header row {la ligne d'en-tête}
            writer.writerow(["Name", "Location", "Grade", "Beta Description"])

    # This loop will run forever until the user chooses to exit.
    while True:
        print("\n===== Climbing Beta App Menu =====")
        print("1. Add a new beta")
        print("2. View all betas")
        print("3. Exit")
        
        choice = input("What do you want to do? (Enter 1, 2, or 3): ")
        
        if choice == '1':
            add_beta()
        elif choice == '2':
            view_betas()
        elif choice == '3':
            print("Goodbye and happy climbing! 💪")
            break # This exits the loop.
        else:
            print("\nInvalid choice. Please enter 1, 2, or 3.")

# This line makes sure the main() function runs when you execute the script.
if __name__ == "__main__":
    main()