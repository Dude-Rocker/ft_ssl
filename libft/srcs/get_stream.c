/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   get_stream.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vgladush <vgladush@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/12/12 09:04:10 by vveselov          #+#    #+#             */
/*   Updated: 2018/09/22 16:19:42 by vgladush         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static char	*mem_join(char *s1, char *s2, size_t i, size_t j)
{
	size_t	z;
	char	*res;

	res = ft_strnew(i + j);
	z = -1;
	while (++z < i)
		res[z] = s1[z];
	while (j--)
		res[z++] = *s2++;
	free(s1);
	return (res);
}

char		*get_stream(const int fd, size_t *size)
{
	char	buf[BUFF_SIZE + 1];
	char	*res;
	size_t	i;
	size_t	j;


	if (read(fd, 0, 0) < 0)
		return 0;
	res = ft_strnew(0);
	j = 0;
	while ((i = read(fd, buf, BUFF_SIZE)) > 0)
	{
		buf[i] = 0;
		res = mem_join(res, buf, j * BUFF_SIZE, i);
		*size = j * BUFF_SIZE + i;
		j++;
	}
	return (res);
}
