#******************************************************************************#
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: vgladush <marvin@42.fr>                    +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2017/10/28 18:18:58 by vgladush          #+#    #+#              #
#    Updated: 2017/10/28 22:57:41 by vgladush         ###   ########.fr        #
#                                                                              #
#******************************************************************************#

NAME	=	libft.a
CMPL	=	gcc
FLGS	=	-Wall -Wextra -Werror -c
FUNC	=	ft_atoi.c ft_bzero.c ft_factorialnb.c ft_isalnum.c ft_isalpha.c \
			ft_isascii.c ft_isdigit.c ft_isprint.c ft_itoa.c ft_lstadd.c \
			ft_lstdel.c ft_lstdelone.c ft_lstiter.c ft_lstmap.c ft_lstnew.c \
			ft_memalloc.c ft_memccpy.c ft_memchr.c ft_memcmp.c ft_memcpy.c \
			ft_memdel.c ft_memmove.c ft_memset.c ft_putchar_fd.c ft_putchar.c \
			ft_putendl_fd.c ft_putendl.c ft_putnbr_fd.c ft_putnbr.c ft_qstr.c \
			ft_putstr_fd.c ft_putstr.c ft_rotnb.c ft_sqrtrd.c ft_strcat.c \
			ft_strchr.c ft_strclr.c ft_strcmp.c ft_strcpy.c ft_putnbri.c \
			ft_strdup.c ft_strequ.c ft_striter.c ft_striteri.c ft_strjoin.c \
			ft_strlcat.c ft_strlen.c ft_strmap.c ft_strmapi.c ft_strncat.c \
			ft_strncmp.c ft_strncpy.c ft_strnequ.c ft_strnew.c ft_strnstr.c \
			ft_strrchr.c ft_strsplit.c ft_strstr.c ft_strsub.c ft_strtrim.c \
			ft_tolower.c ft_toupper.c ft_calc.c ft_replchar.c ft_putarstr.c \
			ft_nbrlen.c get_next_line.c ft_dblhex.c ft_itoabase.c ft_strdel.c \
			ft_prfdbl.c ft_prfnbr.c ft_prfoper.c ft_printf.c ft_joinfree.c \
			ft_unicode.c get_stream.c ft_kickchar.c

DIRF	=	./srcs/
DIRO	=	./objs/
OBJS	=	$(FUNC:.c=.o)
OBJC	=	$(addprefix $(DIRO), $(OBJS))
INCL	=	$(addprefix -I, ./Includes/)

all: $(NAME)

$(NAME): $(OBJC)
	@ar rc $(NAME) $(OBJC)
	@ranlib $(NAME)
	@echo "\x1B[0;32m$(NAME) ready"

$(DIRO)%.o: $(DIRF)%.c
	@mkdir -p $(DIRO)
	@$(CMPL) $(FLGS) $(INCL) -o $@ $<

clean:
	@rm -rf $(DIRO)
	@echo "\x1B[1;31mObjects $(NAME) deleted"

fclean: clean
	@rm -f $(NAME)
	@echo "\x1B[0;31m$(NAME) deleted"

re: fclean all
