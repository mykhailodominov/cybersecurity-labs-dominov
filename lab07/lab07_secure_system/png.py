from PIL import Image

img = Image.new("RGB", (1920, 1080), color="white")
img.save("big_image.png")