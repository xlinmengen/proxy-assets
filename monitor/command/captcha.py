import base64
import random
from io  import BytesIO
from PIL import Image, ImageDraw, ImageFont

def generator(code: str, size: tuple = (150, 50), bg_color: tuple = None) -> str:
    """生成图形验证码"""
    w, h = size
    bg = bg_color or (random.randint(200, 255), random.randint(200, 255), random.randint(200, 255))
    
    img  = Image.new('RGB', (w, h), bg)
    draw = ImageDraw.Draw(img)
    
    # 文字颜色（自动对比背景）
    brightness = (bg[0] * 299 + bg[1] * 587 + bg[2] * 114) / 1000
    def text_rgb_generator():
        return (random.randint(0, 60), random.randint(0, 60), random.randint(0, 60)) if brightness > 128 else (random.randint(195, 255), random.randint(195, 255), random.randint(195, 255))
    
    for _ in range(500):  # 噪点
        draw.point((random.randint(0, w), random.randint(0, h)), fill=(
            random.randint(max(0, bg[0]-40), min(255, bg[0]+40)),
            random.randint(max(0, bg[1]-40), min(255, bg[1]+40)),
            random.randint(max(0, bg[2]-40), min(255, bg[2]+40))
        ))
    for _ in range(6):    # 干扰线
        draw.line((random.randint(0, w), random.randint(0, h), random.randint(0, w), random.randint(0, h)), fill=text_rgb_generator(), width=random.randint(1, 2))
    for _ in range(4):    # 弧线
        x1, x2 = random.randint(0, w//2), random.randint(w//2, w)
        y1, y2 = random.randint(0, h//2), random.randint(h//2, h)
        draw.arc([min(x1,x2), min(y1,y2), max(x1,x2), max(y1,y2)], 0, 360, fill=text_rgb_generator(), width=1)
    
    # 字体
    try   : font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", int(h * 0.5))
    except: font = ImageFont.load_default()
    
    # 字体高度
    try   : font_h = font.getmetrics()[0] + font.getmetrics()[1]
    except: font_h = int(h * 0.5)
    
    # 绘制文字
    spacing = w // (len(code) + 1)
    for i, char in enumerate(code):
        # 创建旋转字符
        text_rgb  = text_rgb_generator()
        char_img  = Image.new('RGBA', (int(h * 0.8), int(h * 0.8)), (0, 0, 0, 0))
        char_draw = ImageDraw.Draw(char_img)
        char_draw.text((char_img.width//2 - int(h*0.5)//2, char_img.height//2 - font_h//2), char, fill=(
            max(0, min(255, text_rgb[0] + random.randint(-30, 30))),
            max(0, min(255, text_rgb[1] + random.randint(-30, 30))),
            max(0, min(255, text_rgb[2] + random.randint(-30, 30)))
        ), font=font)
        rotated = char_img.rotate(random.randint(-25, 25), expand=1)
        
        x = spacing * (i + 1) - int(h * 0.5) // 2 + random.randint(-5, 5)
        y = (h - font_h) // 2 + random.randint(-5, 5)
        img.paste(rotated, (x - rotated.width//2 + int(h*0.5)//2, y - rotated.height//2 + font_h//2), rotated)
    
    buf = BytesIO()
    img.save(buf, format='PNG')
    return f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode()}"