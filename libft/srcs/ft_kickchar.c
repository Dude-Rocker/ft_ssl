/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_kickchar.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: vgladush <vgladush@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/09/01 12:40:29 by vgladush          #+#    #+#             */
/*   Updated: 2018/09/01 12:50:17 by vgladush         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void		ft_kickchar(char *s, char a, char b, char c)
{
	int		i;
	int		j;

	i = 0;
	j = 0;
	while (s[i])
	{
		if ((!a || s[i] != a) && (!b || s[i] != b) && (!c || s[i] != c))
			s[j++] = s[i];
		++i;
	}
	s[j] = 0;
}
