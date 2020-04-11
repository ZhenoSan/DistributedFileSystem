from tkinter import *
import tkinter.filedialog

class TextEditor:

	@staticmethod
	def quit_app(event=None):
		root.quit()


	def save_file(self, event=None):
		file = tkinter.filedialog.asksaveasfile(mode='w')
		if file != None:
		    # Get text in the text widget and delete the last newline
		    data = self.text_area.get('1.0', END + '-1c')
		    # Write the text and close
		    file.write(data)
		    file.close()


	def __init__(self, root, fname):
		self.text_to_write = ""
		root.title("Text Editor")
		root.geometry("600x550")
		frame = Frame(root, width=600, height=550)
		scrollbar = Scrollbar(frame)
		self.text_area = Text(frame, width=600, height=550,
				        yscrollcommand=scrollbar.set,
				        padx=10, pady=10)
		scrollbar.config(command=self.text_area.yview)
		scrollbar.pack(side="right", fill="y")
		self.text_area.pack(side="left", fill="both", expand=True)
		frame.pack()
		the_menu = Menu(root)
		file_menu = Menu(the_menu, tearoff=0)
		file_menu.add_command(label="Save", command=self.save_file)
		file_menu.add_separator()
		file_menu.add_command(label="Quit (unsaved)", command=self.quit_app)
		the_menu.add_cascade(label="File", menu=file_menu)
		root.config(menu=the_menu)
		self.text_area.delete(1.0, END)
		with open(fname) as _file:
			self.text_area.insert(1.0, _file.read())
		root.update_idletasks()


root = Tk()
text_editor = TextEditor(root, )
root.mainloop()
